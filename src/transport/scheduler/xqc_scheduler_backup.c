/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/scheduler/xqc_scheduler_backup.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"

#define BACKUP_PATH_PROBE_SUCCESS_TIMEOUT 3000000
#define BACKUP_PATH_PROBE_TIMEOUT 3000000


static size_t
xqc_backup_scheduler_size()
{
    return 0;
}

static void
xqc_backup_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    return;
}

static inline xqc_bool_t
xqc_path_can_schedule(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    if (path->path_state != XQC_PATH_STATE_ACTIVE) {
        return XQC_FALSE;
    }

    if (packet_out->po_flag & XQC_POF_NOT_SCHEDULE) {
        if ((path->tra_path_status != XQC_TRA_PATH_STATUS_IN_USE) && (path->parent_conn->in_use_active_path_count > 0)) {
            return XQC_FALSE;
        }
    }

    return XQC_TRUE;
}

static inline xqc_bool_t
xqc_path_can_reinject(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    if (path->path_state != XQC_PATH_STATE_ACTIVE) {
        return XQC_FALSE;
    }

    if (path->path_id == packet_out->po_path_id) {
        return XQC_FALSE;
    }

    if (packet_out->po_flag & XQC_POF_NOT_REINJECT) {
        if ((path->tra_path_status != XQC_TRA_PATH_STATUS_IN_USE) && (path->app_path_status != XQC_APP_PATH_STATUS_AVAILABLE)) {
            return XQC_FALSE;
        }
    }

    return XQC_TRUE;
}

static inline xqc_bool_t
xqc_path_can_probe(xqc_path_ctx_t *path)
{
    return (path->path_state == XQC_PATH_STATE_ACTIVE)
        && (path->tra_path_status == XQC_TRA_PATH_STATUS_BACKUP);
}

xqc_path_ctx_t *
xqc_backup_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd, int reinject)
{
    xqc_path_ctx_t *best_path = NULL;

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_send_ctl_t *send_ctl;

    /* min RTT */
    uint64_t min_rtt = XQC_MAX_UINT64_VALUE;
    uint64_t path_srtt;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (reinject) {
            if (!xqc_path_can_reinject(path, packet_out)) {
                continue;
            }

        } else {
            if (!xqc_path_can_schedule(path, packet_out)) {
                continue;
            }
        }

        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }

        path_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|path srtt|conn:%p|path_id:%ui|path_srtt:%ui|", 
                conn, path->path_id, path_srtt);

        if (path_srtt < min_rtt) {
            best_path = path;
            min_rtt = path_srtt;
        }
    }

    if (best_path == NULL) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|No available paths to schedule|conn:%p|", conn);

    } else {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|best path:%ui|frame_type:%s|",
                best_path->path_id, xqc_frame_type_2_str(packet_out->po_frame_types));
    }

    return best_path;

}

static inline xqc_int_t
xqc_backup_probe_standby_path(xqc_connection_t *conn,
    xqc_path_ctx_t **default_path, xqc_path_ctx_t **standby_path)
{
    xqc_int_t ret;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_send_ctl_t *send_ctl;

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t last_time;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        if (path->app_path_status == XQC_APP_PATH_STATUS_AVAILABLE) {
            *default_path = path;

        } else if (path->app_path_status == XQC_APP_PATH_STATUS_STANDBY) {
            *standby_path = path;
        }

        if (conn->conn_settings.standby_path_probe_timeout > 0
            && xqc_path_can_probe(path))
        {
            send_ctl = path->path_send_ctl;
            last_time = send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[XQC_PNS_APP_DATA];

            if ((now - last_time) >= conn->conn_settings.standby_path_probe_timeout * 1000) {
                ret = xqc_path_standby_probe(path);
                if (ret != XQC_OK) {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_path_standby_probe error|");
                    return ret;
                }
            }

        }
    }

    return XQC_OK;
}

static inline xqc_bool_t
xqc_default_path_is_in_use(xqc_path_ctx_t *default_path, xqc_path_ctx_t *standby_path)
{
    return (default_path->tra_path_status == XQC_TRA_PATH_STATUS_IN_USE)
        && (standby_path->tra_path_status == XQC_TRA_PATH_STATUS_BACKUP);
}

static inline xqc_bool_t
xqc_standby_path_is_in_use(xqc_path_ctx_t *default_path, xqc_path_ctx_t *standby_path)
{
    return (default_path->tra_path_status == XQC_TRA_PATH_STATUS_BACKUP)
        && (standby_path->tra_path_status == XQC_TRA_PATH_STATUS_IN_USE);
}

static inline xqc_bool_t
xqc_default_path_need_degrade(xqc_connection_t *conn,
    xqc_path_ctx_t *default_path, xqc_path_ctx_t *standby_path)
{
    if (conn->transport_cbs.path_status_controller) {
        return conn->transport_cbs.path_status_controller(conn, &conn->scid_set.user_scid,
                                                          default_path->path_id, XQC_PATH_DEGRADE,
                                                          xqc_conn_get_user_data(conn));
    }

    xqc_send_ctl_t *send_ctl = default_path->path_send_ctl;
    if (send_ctl->ctl_pto_count_since_last_tra_path_status_changed > conn->conn_settings.path_unreachable_pto_count) {
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

static inline xqc_bool_t
xqc_default_path_need_recovery(xqc_connection_t *conn,
    xqc_path_ctx_t *default_path, xqc_path_ctx_t *standby_path)
{
    if (conn->transport_cbs.path_status_controller) {
        return conn->transport_cbs.path_status_controller(conn, &conn->scid_set.user_scid,
                                                          default_path->path_id, XQC_PATH_RECOVERY,
                                                          xqc_conn_get_user_data(conn));
    }

    xqc_send_ctl_t *send_ctl = default_path->path_send_ctl;
    if (send_ctl->ctl_send_count - send_ctl->ctl_send_count_at_last_tra_path_status_changed_time > 3
        && xqc_monotonic_timestamp() - default_path->last_tra_path_status_changed_time > BACKUP_PATH_PROBE_TIMEOUT
        && send_ctl->ctl_pto_count_since_last_tra_path_status_changed < 1)
    {
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

void
xqc_probe_before_use(xqc_connection_t *conn,
    xqc_path_ctx_t *next_in_use_path, xqc_path_ctx_t *next_backup_path)
{
    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t last_recv_time = next_in_use_path->path_send_ctl->ctl_largest_recv_time[XQC_PNS_APP_DATA];
    xqc_usec_t last_send_time = next_in_use_path->path_send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[XQC_PNS_APP_DATA];

    if ((now - last_recv_time) <= BACKUP_PATH_PROBE_SUCCESS_TIMEOUT) {
        xqc_set_transport_path_status(next_in_use_path, XQC_TRA_PATH_STATUS_IN_USE, now);
        xqc_set_transport_path_status(next_backup_path, XQC_TRA_PATH_STATUS_BACKUP, now);

    } else if ((now - last_send_time) >= BACKUP_PATH_PROBE_TIMEOUT) {
        xqc_int_t ret = xqc_path_standby_probe(next_in_use_path);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_path_standby_probe error|");
            return;
        }
    }
}


void
xqc_backup_scheduler_handle_conn_event(void *scheduler, 
    xqc_connection_t *conn, xqc_scheduler_conn_event_t event, void *event_arg)
{
    if (event == XQC_SCHED_EVENT_CONN_ROUND_START) {

        if (conn->active_path_count < 2) {
            return;
        }

        if (XQC_UNLIKELY(conn->conn_state >= XQC_CONN_STATE_CLOSING)) {
            return;
        }

        xqc_int_t ret = XQC_ERROR;

        xqc_path_ctx_t *default_path = NULL;
        xqc_path_ctx_t *standby_path = NULL;

        ret = xqc_backup_probe_standby_path(conn, &default_path, &standby_path);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_backup_probe_standby_path error|ret:%d|", ret);
            return;
        }

        if (default_path == NULL || standby_path == NULL) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|identify default/standby path error|");
            return;
        }

        if (xqc_default_path_is_in_use(default_path, standby_path)) {
            if (xqc_default_path_need_degrade(conn, default_path, standby_path)) {
                xqc_probe_before_use(conn, standby_path, default_path);
            }

        } else if (xqc_standby_path_is_in_use(default_path, standby_path)) {
            if (xqc_default_path_need_recovery(conn, default_path, standby_path)) {
                xqc_probe_before_use(conn,default_path, standby_path);
            }

        } else {
            xqc_log(conn->log, XQC_LOG_ERROR, "|path status error|");
            return;
        }
    }

}

const xqc_scheduler_callback_t xqc_backup_scheduler_cb = {
    .xqc_scheduler_size             = xqc_backup_scheduler_size,
    .xqc_scheduler_init             = xqc_backup_scheduler_init,
    .xqc_scheduler_get_path         = xqc_backup_scheduler_get_path,
    .xqc_scheduler_handle_conn_event = xqc_backup_scheduler_handle_conn_event,
};