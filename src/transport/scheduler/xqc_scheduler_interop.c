/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/scheduler/xqc_scheduler_interop.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"


static size_t
xqc_interop_scheduler_size()
{
    return 0;
}

static void
xqc_interop_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    return;
}

xqc_path_ctx_t *
xqc_interop_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd, int reinject,
    xqc_bool_t *cc_blocked)
{
    xqc_path_ctx_t *best_path = NULL;
    xqc_path_ctx_t *best_standby_path = NULL;

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    
    xqc_send_ctl_t *send_ctl;

    /* min RTT */
    uint64_t min_rtt = XQC_MAX_UINT64_VALUE;
    uint64_t min_rtt_standby = XQC_MAX_UINT64_VALUE;
    uint64_t path_srtt;
    uint32_t avail_path_cnt = 0;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        if (path->app_path_status == XQC_APP_PATH_STATUS_AVAILABLE) {
            avail_path_cnt++;
        }

        if (reinject && (packet_out->po_path_id == path->path_id)) {
            continue;
        }

        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked) {
                *cc_blocked = XQC_TRUE;
            }
        }

        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        path_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|path srtt|conn:%p|path_id:%ui|path_srtt:%ui|", 
                conn, path->path_id, path_srtt);

        if (path_srtt < min_rtt) {
            if (path->app_path_status == XQC_APP_PATH_STATUS_AVAILABLE) {
                best_path = path;
                min_rtt = path_srtt;
            } else {
                best_standby_path = path;
                min_rtt_standby = path_srtt;
            }
        }
    }

    if (best_path == NULL) {
        if (avail_path_cnt > 0 || best_standby_path == NULL) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|No available paths to schedule|conn:%p|", conn);

        } else {
            best_path = best_standby_path;
        }

    }

    if (best_path) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|best path:%ui|frame_type:%s|app_status:%d|",
                best_path->path_id, xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
                best_path->app_path_status);
    }

    return best_path;
}

const xqc_scheduler_callback_t xqc_interop_scheduler_cb = {
    .xqc_scheduler_size             = xqc_interop_scheduler_size,
    .xqc_scheduler_init             = xqc_interop_scheduler_init,
    .xqc_scheduler_get_path         = xqc_interop_scheduler_get_path,
};