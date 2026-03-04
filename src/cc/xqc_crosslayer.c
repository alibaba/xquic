#include "src/cc/xqc_crosslayer.h"

#include <xquic/xquic.h>
#include <string.h>

#include "src/transport/xqc_conn.h"

#define DEFAULT_MIN_UPDATE_INTERVAL_US  50000   /* 50ms */
#define DEFAULT_MIN_PACING_GAIN         0.5f
#define DEFAULT_MAX_PACING_GAIN         2.0f

void
xqc_crosslayer_init(xqc_crosslayer_ctl_t *ctl,
    xqc_connection_t *conn, const xqc_crosslayer_config_t *config)
{
    memset(ctl, 0, sizeof(*ctl));
    ctl->conn = conn;

    if (config) {
        ctl->min_update_interval_us = (xqc_usec_t)config->min_update_interval_us;
        ctl->min_pacing_gain = config->min_pacing_gain;
        ctl->max_pacing_gain = config->max_pacing_gain;
        ctl->min_pacing_rate = config->min_pacing_rate;
    }

    if (ctl->min_update_interval_us == 0) {
        ctl->min_update_interval_us = DEFAULT_MIN_UPDATE_INTERVAL_US;
    }
    if (ctl->min_pacing_gain <= 0.0f) {
        ctl->min_pacing_gain = DEFAULT_MIN_PACING_GAIN;
    }
    if (ctl->max_pacing_gain <= 0.0f) {
        ctl->max_pacing_gain = DEFAULT_MAX_PACING_GAIN;
    }
}

xqc_int_t
xqc_crosslayer_apply(xqc_crosslayer_ctl_t *ctl,
    const xqc_crosslayer_event_t *event, xqc_usec_t now)
{
    if (ctl == NULL || event == NULL || ctl->conn == NULL) {
        return -XQC_EPARAM;
    }

    switch (event->type) {
    case XQC_EVENT_PACING_GAIN_UPDATE: {
        if (ctl->last_gain_update > 0
            && now - ctl->last_gain_update < ctl->min_update_interval_us)
        {
            xqc_log(ctl->conn->log, XQC_LOG_DEBUG,
                "|crosslayer_rate_limited|type:PACING_GAIN|interval:%ui|",
                now - ctl->last_gain_update);
            return XQC_ERROR;
        }

        float g = event->payload.pacing_gain.gain;
        float raw_g = g;
        if (g < ctl->min_pacing_gain) {
            g = ctl->min_pacing_gain;
        }
        if (g > ctl->max_pacing_gain) {
            g = ctl->max_pacing_gain;
        }

        xqc_pacing_gain_update_t u;
        u.pacing_gain = g;
        u.expire_time = event->payload.pacing_gain.expire_us;
        xqc_int_t rc = xqc_conn_signal_x_layer_app_event(ctl->conn,
            XQC_APP_EVENT_PACING_GAIN_UPDATED, &u);
        ctl->last_gain_update = now;
        if (rc == XQC_OK) {
            ctl->dispatch_count++;
            ctl->last_dispatched_gain = g;
        }

        xqc_log(ctl->conn->log, XQC_LOG_STATS,
            "|crosslayer_dispatch|type:PACING_GAIN|raw_gain:%.3f|clamped_gain:%.3f|expire:%ui|cc_handled:%d|dispatch_n:%ui|",
            raw_g, g, u.expire_time, (rc == XQC_OK), ctl->dispatch_count);
        break;
    }

    case XQC_EVENT_PACING_RATE_UPDATE: {
        if (ctl->last_rate_update > 0
            && now - ctl->last_rate_update < ctl->min_update_interval_us)
        {
            xqc_log(ctl->conn->log, XQC_LOG_DEBUG,
                "|crosslayer_rate_limited|type:PACING_RATE|interval:%ui|",
                now - ctl->last_rate_update);
            return XQC_ERROR;
        }

        uint64_t rate = event->payload.pacing_rate.rate;
        uint64_t raw_rate = rate;
        if (rate < ctl->min_pacing_rate) {
            rate = ctl->min_pacing_rate;
        }

        xqc_pacing_rate_update_t u;
        u.pacing_rate = rate;
        u.expire_time = event->payload.pacing_rate.expire_us;
        xqc_int_t rc = xqc_conn_signal_x_layer_app_event(ctl->conn,
            XQC_APP_EVENT_PACING_RATE_UPDATED, &u);
        ctl->last_rate_update = now;
        if (rc == XQC_OK) {
            ctl->dispatch_count++;
            ctl->last_dispatched_rate = rate;
        }

        xqc_log(ctl->conn->log, XQC_LOG_STATS,
            "|crosslayer_dispatch|type:PACING_RATE|raw_rate:%ui|clamped_rate:%ui|expire:%ui|cc_handled:%d|dispatch_n:%ui|",
            raw_rate, rate, u.expire_time, (rc == XQC_OK), ctl->dispatch_count);
        break;
    }

    case XQC_EVENT_TARGET_BITRATE_UPDATE: {
        xqc_target_bitrate_update_t u;
        u.target_bitrate = event->payload.target_bitrate.bitrate;
        u.expire_time = event->payload.target_bitrate.expire_us;
        xqc_int_t rc = xqc_conn_signal_x_layer_app_event(ctl->conn,
            XQC_APP_EVENT_TARGET_BITRATE_UPDATED, &u);
        if (rc == XQC_OK) {
            ctl->dispatch_count++;
        }

        xqc_log(ctl->conn->log, XQC_LOG_STATS,
            "|crosslayer_dispatch|type:TARGET_BITRATE|bitrate:%ui|expire:%ui|cc_handled:%d|dispatch_n:%ui|",
            u.target_bitrate, u.expire_time, (rc == XQC_OK), ctl->dispatch_count);
        break;
    }

    default:
        return -XQC_EPARAM;
    }

    return XQC_OK;
}
