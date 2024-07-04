/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/scheduler/xqc_scheduler_backup.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"


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


xqc_path_ctx_t *
xqc_backup_scheduler_get_path(void *scheduler, xqc_connection_t *conn, 
    xqc_packet_out_t *packet_out, int check_cwnd, int reinject, 
    xqc_bool_t *cc_blocked)
{
    xqc_path_ctx_t *best_path[XQC_PATH_CLASS_PERF_CLASS_SIZE] = { NULL };
    xqc_bool_t has_path[XQC_PATH_CLASS_PERF_CLASS_SIZE] = { XQC_FALSE };
    xqc_path_perf_class_t path_class;
    xqc_bool_t available_path_exists;

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_send_ctl_t *send_ctl;
    xqc_bool_t path_can_send = XQC_FALSE;

    /* min RTT */
    uint64_t path_srtt = 0;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        path_class = xqc_path_get_perf_class(path);

        /* skip inactive paths */
        /* skip frozen paths */
        if (path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN
            || (reinject && (packet_out->po_path_id == path->path_id))) 
        {
            goto skip_path;
        }

        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked) {
                *cc_blocked = XQC_TRUE;
            }
        }

        has_path[path_class] = XQC_TRUE;
        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd);

        if (!path_can_send) {
            goto skip_path;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        path_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        
        if (best_path[path_class] == NULL 
            || path_srtt < xqc_send_ctl_get_srtt(best_path[path_class]->path_send_ctl))
        {
            best_path[path_class] = path;
        }

skip_path:
        xqc_log(conn->log, XQC_LOG_DEBUG, 
                "|path srtt|conn:%p|path_id:%ui|path_srtt:%ui|path_class:%d|"
                "can_send:%d|path_status:%d|path_state:%d|reinj:%d|"
                "pkt_path_id:%ui|best_path:%i|", 
                conn, path->path_id, path_srtt, path_class, path_can_send,
                path->app_path_status, path->path_state, reinject, 
                packet_out->po_path_id,
                best_path[path_class] ? best_path[path_class]->path_id : -1);
    }

    available_path_exists = XQC_FALSE;

    for (path_class = XQC_PATH_CLASS_AVAILABLE_HIGH; 
         path_class < XQC_PATH_CLASS_PERF_CLASS_SIZE; 
         path_class++)
    {
        if (has_path[path_class] && ((path_class & 1) == 0)) {
            available_path_exists = XQC_TRUE;
        }

        /* 
         * do not use a standby path if there 
         * is an available path with higher performence level
         */
        if (best_path[path_class] != NULL) {

            if (available_path_exists && (path_class & 1) && !reinject) {
                /* skip standby path*/
                xqc_log(conn->log, XQC_LOG_DEBUG, 
                        "|skip_standby_path|path_class:%d|path_id:%ui|",
                        path_class, best_path[path_class]->path_id);
                continue;

            } else {
                xqc_log(conn->log, XQC_LOG_DEBUG, "|best path:%ui|frame_type:%s|"
                        "pn:%ui|size:%ud|reinj:%d|path_class:%d|",
                        best_path[path_class]->path_id, 
                        xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
                        packet_out->po_pkt.pkt_num,
                        packet_out->po_used_size, reinject, path_class);
                return best_path[path_class];
            }
        }
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, 
            "|No available paths to schedule|conn:%p|", conn);
    return NULL;
}

void 
xqc_backup_scheduler_handle_conn_event(void *scheduler, 
    xqc_connection_t *conn, xqc_scheduler_conn_event_t event, void *event_arg)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_send_ctl_t *send_ctl;
    xqc_usec_t now = 0, deadline;

    if (event == XQC_SCHED_EVENT_CONN_ROUND_START 
        && conn->conn_settings.standby_path_probe_timeout
        && conn->enable_multipath
        && (conn->conn_state == XQC_CONN_STATE_ESTABED)) 
    {
        /* check if we need to probe standby paths */
        xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
            path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
            if (path->path_state == XQC_PATH_STATE_ACTIVE
                && path->app_path_status == XQC_APP_PATH_STATUS_STANDBY)
            {
                if (!now) {
                    now = xqc_monotonic_timestamp();
                }

                send_ctl = path->path_send_ctl;

                deadline = send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[XQC_PNS_APP_DATA] + conn->conn_settings.standby_path_probe_timeout * 1000;

                xqc_log(conn->log, XQC_LOG_DEBUG, "|standby_probe|path:%ui|deadline:%ui|now:%ui|now>=deadline:%d|last_send:%ui|",
                        path->path_id, deadline, now, now >= deadline, send_ctl->ctl_time_of_last_sent_ack_eliciting_packet[XQC_PNS_APP_DATA]);

                if (now >= deadline) {
                    xqc_path_standby_probe(path);
                }
            }
        }
    }
}

const xqc_scheduler_callback_t xqc_backup_scheduler_cb = {
    .xqc_scheduler_size      = xqc_backup_scheduler_size,
    .xqc_scheduler_init      = xqc_backup_scheduler_init,
    .xqc_scheduler_get_path  = xqc_backup_scheduler_get_path,
    .xqc_scheduler_handle_conn_event = xqc_backup_scheduler_handle_conn_event,
};