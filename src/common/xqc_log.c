/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_log.h"
#include "src/transport/xqc_engine.h"

#ifdef PRINT_MALLOC
FILE *g_malloc_info_fp;
#endif

void
xqc_log_disable(xqc_engine_t *engine, xqc_bool_t disable)
{
    engine->log_disable = disable;
    xqc_log(engine->log, XQC_LOG_DEBUG, "|log_disable:%d|", disable);
}

void
xqc_log_level_set(xqc_log_t *log, xqc_log_level_t level)
{
    log->log_level = level;
}

xqc_log_type_t
xqc_log_event_type(xqc_log_level_t level)
{
    switch (level) {
    case XQC_LOG_REPORT:
        return GEN_REPORT;
    case XQC_LOG_FATAL:
        return GEN_FATAL;
    case XQC_LOG_ERROR:
        return GEN_ERROR;
    case XQC_LOG_WARN:
        return GEN_WARN;
    case XQC_LOG_STATS:
        return GEN_STATS;
    case XQC_LOG_INFO:
        return GEN_INFO;
    case XQC_LOG_DEBUG:
        return GEN_DEBUG;
    default:
        return GEN_DEBUG;
    }
}

xqc_log_level_t
xqc_log_type_2_level(xqc_log_type_t type)
{
    switch (type) {
    case GEN_REPORT:
        return XQC_LOG_REPORT;
    case GEN_FATAL:
        return XQC_LOG_FATAL;
    case GEN_ERROR:
        return XQC_LOG_ERROR;
    case GEN_WARN:
        return XQC_LOG_WARN;
    case GEN_STATS:
        return XQC_LOG_STATS;
    case GEN_INFO:
        return XQC_LOG_INFO;
    case GEN_DEBUG:
        return XQC_LOG_DEBUG;
    default:
        return XQC_LOG_DEBUG;
    }
}

qlog_event_importance_t
xqc_qlog_event_2_level(xqc_log_type_t type)
{
    switch (type) {
    /* draft-ietf-quic-qlog-quic-events */
    case CON_SERVER_LISTENING:
        return EVENT_IMPORTANCE_EXTRA;
    case CON_CONNECTION_STARTED:
    case CON_CONNECTION_CLOSED:
    case CON_CONNECTION_ID_UPDATED:
    case CON_SPIN_BIM_UPDATED:
    case CON_CONNECTION_STATE_UPDATED:
    case CON_PATH_ASSIGNED:
        return EVENT_IMPORTANCE_BASE;

    case CON_MTU_UPDATED:
        return EVENT_IMPORTANCE_EXTRA;

    case TRA_VERSION_INFORMATION:
    case TRA_ALPN_INFORMATION:
    case TRA_PARAMETERS_SET:
        return EVENT_IMPORTANCE_CORE;

    case TRA_PARAMETERS_RESTORED:
        return EVENT_IMPORTANCE_BASE;
    
    case TRA_PACKET_SENT:
    case TRA_PACKET_RECEIVED:
        return EVENT_IMPORTANCE_CORE;

    case TRA_PACKET_DROPPED:
    case TRA_PACKET_BUFFERED:
        return EVENT_IMPORTANCE_BASE;

    case TRA_PACKETS_ACKED:
    case TRA_DATAGRAM_DROPPED:
    case TRA_DATAGRAMS_SENT:
    case TRA_DATAGRAMS_RECEIVED:
        return EVENT_IMPORTANCE_EXTRA;
    
    case TRA_STREAM_STATE_UPDATED:
        return EVENT_IMPORTANCE_BASE;
        
    case TRA_FRAMES_PROCESSED:
        return EVENT_IMPORTANCE_EXTRA;

    case TRA_STREAM_DATA_MOVED:
    case TRA_DATAGRAM_DATA_MOVED:
        return EVENT_IMPORTANCE_BASE;

    case REC_METRICS_UPDATED:
        return EVENT_IMPORTANCE_EXTRA;

    case SEC_KEY_UPDATED:
    case SEC_KEY_RETIRED:
        return EVENT_IMPORTANCE_BASE;

    case REC_PARAMETERS_SET:
        return EVENT_IMPORTANCE_BASE;

    case REC_CONGESTION_STATE_UPDATED:
        return EVENT_IMPORTANCE_BASE;

    case REC_LOSS_TIMER_UPDATED:
        return EVENT_IMPORTANCE_EXTRA;

    case REC_PACKET_LOST:
        return EVENT_IMPORTANCE_CORE;

    case REC_MARKED_FOR_RETRANSMIT:
        return EVENT_IMPORTANCE_EXTRA;

    /* draft-ietf-quic-qlog-h3-events */
    case HTTP_PARAMETERS_SET:
    case HTTP_PARAMETERS_RESTORED:
    case HTTP_STREAM_TYPE_SET:
    case HTTP_PRIORITY_UPDATED:
        return EVENT_IMPORTANCE_BASE;

    case HTTP_FRAME_PARSED:
    case HTTP_FRAME_CREATED:
        return EVENT_IMPORTANCE_CORE;

    case HTTP_PUSH_RESOLVED:
        return EVENT_IMPORTANCE_EXTRA;

    /* quic-qlog-h3-events have removed all qpack event definitions since draft 05*/
    case QPACK_STATE_UPDATED:
    case QPACK_STREAM_STATE_UPDATED:
    case QPACK_DYNAMIC_TABLE_UPDATED:
    case QPACK_HEADERS_ENCODED:
    case QPACK_HEADERS_DECODED:
    case QPACK_INSTRUCTION_CREATED:
    case QPACK_INSTRUCTION_PARSED:
        return EVENT_IMPORTANCE_REMOVED;
    default:
        return EVENT_IMPORTANCE_EXTRA;
    }
}

xqc_log_level_t
qlog_importance_2_log_level(xqc_log_type_t type){
    if (type >= GEN_REPORT){
        return xqc_log_type_2_level(type);
    }
    switch (type)
    {
    /* datagrame, packet, frame level event should be xqc_log_debug */
    case HTTP_FRAME_PARSED:
    case HTTP_FRAME_CREATED:
    case TRA_PACKETS_ACKED:
    case TRA_DATAGRAM_DROPPED:
    case TRA_DATAGRAMS_SENT:
    case TRA_DATAGRAMS_RECEIVED:
    case TRA_PACKET_SENT:
    case TRA_PACKET_RECEIVED:
    case TRA_FRAMES_PROCESSED:
    case TRA_STREAM_DATA_MOVED:
    case TRA_DATAGRAM_DATA_MOVED:
    case REC_LOSS_TIMER_UPDATED:
    case REC_PACKET_LOST:
    case REC_MARKED_FOR_RETRANSMIT:
    case TRA_PACKET_DROPPED:
    case TRA_PACKET_BUFFERED:
        return XQC_LOG_DEBUG;
    
    default:
        return XQC_LOG_INFO;
    }
}

const char *
xqc_log_type_str(xqc_log_type_t type)
{
    static const char *event_type2str[] = {
            [CON_SERVER_LISTENING]              = "server_listening",
            [CON_CONNECTION_STARTED]            = "connection_started",
            [CON_CONNECTION_CLOSED]             = "connection_closed",
            [CON_CONNECTION_ID_UPDATED]         = "connection_id_updated",
            [CON_SPIN_BIM_UPDATED]              = "spin_bin_updated",
            [CON_CONNECTION_STATE_UPDATED]      = "connection_state_updated",
            [CON_PATH_ASSIGNED]                 = "path_assigned",
            [CON_MTU_UPDATED]                   = "mtu_updated",
            [SEC_KEY_UPDATED]                   = "key_updated",
            [SEC_KEY_RETIRED]                   = "key_retired",
            [TRA_VERSION_INFORMATION]           = "version_information",
            [TRA_ALPN_INFORMATION]              = "alpn_information",
            [TRA_PARAMETERS_SET]                = "tra_parameters_set",
            [TRA_PARAMETERS_RESTORED]           = "tra_parameters_restored",
            [TRA_PACKET_SENT]                   = "packet_sent",
            [TRA_PACKET_RECEIVED]               = "packet_received",
            [TRA_PACKET_DROPPED]                = "packet_dropped",
            [TRA_PACKET_BUFFERED]               = "packet_buffered",
            [TRA_PACKETS_ACKED]                 = "packets_acked",
            [TRA_DATAGRAMS_SENT]                = "datagrams_sent",
            [TRA_DATAGRAMS_RECEIVED]            = "datagrams_received",
            [TRA_DATAGRAM_DROPPED]              = "datagram_dropped",
            [TRA_STREAM_STATE_UPDATED]          = "stream_state_updated",
            [TRA_FRAMES_PROCESSED]              = "frames_processed",
            [TRA_STREAM_DATA_MOVED]             = "stream_data_moved",
            [TRA_DATAGRAM_DATA_MOVED]           = "datagram_data_moved",
            [TRA_STATELESS_RESET]               = "stateless_reset",
            [REC_PARAMETERS_SET]                = "rec_parameters_set",
            [REC_METRICS_UPDATED]               = "rec_metrics_updated",
            [REC_CONGESTION_STATE_UPDATED]      = "congestion_state_updated",
            [REC_LOSS_TIMER_UPDATED]            = "loss_timer_updated",
            [REC_PACKET_LOST]                   = "packet_lost",
            [REC_MARKED_FOR_RETRANSMIT]         = "marked_for_retransmit",
            [HTTP_PARAMETERS_SET]               = "http_parameters_set",
            [HTTP_PARAMETERS_RESTORED]          = "http_parameters_restored",
            [HTTP_STREAM_TYPE_SET]              = "http_stream_type_set",
            [HTTP_PRIORITY_UPDATED]             = "http_priority_updated",
            [HTTP_FRAME_CREATED]                = "http_frame_created",
            [HTTP_FRAME_PARSED]                 = "http_frame_parsed",
            [HTTP_PUSH_RESOLVED]                = "push_resolved",
            [QPACK_STATE_UPDATED]               = "qpack_state_updated",
            [QPACK_STREAM_STATE_UPDATED]        = "qpack_stream_state_updated",
            [QPACK_DYNAMIC_TABLE_UPDATED]       = "dynamic_table_updated",
            [QPACK_HEADERS_ENCODED]             = "headers_encoded",
            [QPACK_HEADERS_DECODED]             = "headers_decoded",
            [QPACK_INSTRUCTION_CREATED]         = "instruction_created",
            [QPACK_INSTRUCTION_PARSED]          = "instruction_parsed",
            [GEN_REPORT]                        = "report",
            [GEN_FATAL]                         = "fatal",
            [GEN_ERROR]                         = "error",
            [GEN_WARN]                          = "warn",
            [GEN_STATS]                         = "stats",
            [GEN_INFO]                          = "info",
            [GEN_DEBUG]                         = "debug",
    };
    return event_type2str[type];
}


void
xqc_log_implement(xqc_log_t *log, xqc_log_type_t type, const char *func, const char *fmt, ...)
{
    /* do nothing if switch is off */
    if (log->engine && log->engine->log_disable) {
        return;
    }

    xqc_log_level_t level = xqc_log_type_2_level(type);
    if (level > log->log_level) {
        return;
    }

    unsigned char   buf[XQC_MAX_LOG_LEN] = {0};
    unsigned char  *p = buf;
    unsigned char  *last = buf + sizeof(buf);

    /* do not need time & level if use outside log format */
    if (log->log_timestamp) {
        /* time */
        char time[64];
        xqc_log_time(time, sizeof(time));
        p = xqc_sprintf(p, last, "[%s] ", time);
    }

    if (log->log_level_name) {
        /* log level */
        p = xqc_sprintf(p, last, "[%s] ", xqc_log_type_str(type));
    }

    if (log->scid != NULL) {
        p = xqc_sprintf(p, last, "|scid:%s|%s", log->scid, func);
    } else {
        p = xqc_sprintf(p, last, "|%s", func);
    }

    /* log */
    va_list args;
    va_start(args, fmt);
    p = xqc_vsprintf(p, last, fmt, args);
    va_end(args);

    if (p + 1 < last) {
        /* may use printf("%s") outside, add '\0' and don't count into size */
        *p = '\0';
    }

    /* XQC_LOG_STATS & XQC_LOG_REPORT are levels for statistic */
    if ((level == XQC_LOG_STATS || level == XQC_LOG_REPORT)
        && log->log_callbacks->xqc_log_write_stat)
    {
        log->log_callbacks->xqc_log_write_stat(level, buf, p - buf, log->user_data);

    } else if (log->log_callbacks->xqc_log_write_err) {
        log->log_callbacks->xqc_log_write_err(level, buf, p - buf, log->user_data);
    }

    /* if didn't set log callback, just return */
}

void
xqc_qlog_implement(xqc_log_t *log, xqc_log_type_t type, const char *func, const char *fmt, ...)
{
    /* do nothing if switch is off */
    if (log->engine && log->engine->log_disable) {
        return;
    }

    if (!log->log_event){
        return;
    }

    qlog_event_importance_t event_imp = xqc_qlog_event_2_level(type);
    /* EVENT_IMPORTANCE_SELECTED: events will be emitted based on their map log level and cur log level */
    xqc_log_level_t level = XQC_LOG_DEBUG;
    if (log->qlog_importance == EVENT_IMPORTANCE_SELECTED) {
        level = qlog_importance_2_log_level(type);
        if (level > log->log_level) {
            return;
        }
    }

    unsigned char   buf[XQC_MAX_LOG_LEN] = {0};
    unsigned char  *p = buf;
    unsigned char  *last = buf + sizeof(buf);

    /* do not need time & level if use outside log format */
    if (log->log_timestamp) {
        /* time */
        char time[64];
        xqc_log_time(time, sizeof(time));
        p = xqc_sprintf(p, last, "[%s] ", time);
    }

    if (log->log_level_name) {
        /* qlog event */
        p = xqc_sprintf(p, last, "[%s] ", xqc_log_type_str(type));
    }

    if (log->scid != NULL) {
        p = xqc_sprintf(p, last, "|scid:%s|%s", log->scid, func);
    } else {
        p = xqc_sprintf(p, last, "|%s", func);
    }

    /* log */
    va_list args;
    va_start(args, fmt);
    p = xqc_vsprintf(p, last, fmt, args);
    va_end(args);

    if (p + 1 < last) {
        /* may use printf("%s") outside, add '\0' and don't count into size */
        *p = '\0';
    }
    /* EVENT_IMPORTANCE_SELECTED: event logs output with xqc_log via xqc_log_write_err callback */
    if (log->qlog_importance == EVENT_IMPORTANCE_SELECTED) {
        if (log->log_callbacks->xqc_log_write_err) {
            log->log_callbacks->xqc_log_write_err(level, buf, p - buf, log->user_data);
        }
    }
    else if(log->log_callbacks->xqc_qlog_event_write) {
        log->log_callbacks->xqc_qlog_event_write(event_imp, buf, p - buf, log->user_data);
    }
}


void
xqc_log_time(char *buf, size_t buf_len)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm tm;

#ifdef XQC_SYS_WINDOWS
    time_t t = tv.tv_sec;
#ifdef _USE_32BIT_TIME_T
    _localtime32_s(&tm, &t);
#else
    _localtime64_s(&tm, &t);
#endif

#else
    localtime_r(&tv.tv_sec, &tm);
#endif
    tm.tm_mon++;
    tm.tm_year += 1900;

#ifdef __APPLE__
    snprintf(buf, buf_len, "%4d/%02d/%02d %02d:%02d:%02d %06d",
             tm.tm_year, tm.tm_mon,
             tm.tm_mday, tm.tm_hour,
             tm.tm_min, tm.tm_sec, tv.tv_usec);
#else
    snprintf(buf, buf_len, "%4d/%02d/%02d %02d:%02d:%02d %06ld",
             tm.tm_year, tm.tm_mon,
             tm.tm_mday, tm.tm_hour,
             tm.tm_min, tm.tm_sec, tv.tv_usec);
#endif
}
