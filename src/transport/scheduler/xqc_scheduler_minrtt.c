/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/scheduler/xqc_scheduler_minrtt.h"

#include "src/transport/xqc_send_ctl.h"


static size_t
xqc_minrtt_scheduler_size()
{
    return 0;
}

static void
xqc_minrtt_scheduler_init(void *scheduler, xqc_log_t *log)
{
    return;
}

static xqc_bool_t
xqc_path_schedule_check_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int check_cwnd)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint32_t schedule_bytes = path->path_schedule_bytes;

    /* normal packets in send list will be blocked by cc */
    if (check_cwnd && XQC_CAN_IN_FLIGHT(packet_out->po_frame_types)) {
        if (!xqc_send_ctl_can_send(send_ctl, packet_out, schedule_bytes)) {
            xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
                    "|path:%ui|blocked by cc|", path->path_id);
            return XQC_FALSE;
        }
    }

    return XQC_TRUE;
}

static  xqc_path_ctx_t *
xqc_minrtt_scheduler_get_path(void *scheduler,
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

        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        if (reinject && (packet_out->po_path_id == path->path_id)) {
            continue;
        }

        if (!xqc_path_schedule_check_can_send(path, packet_out, check_cwnd)) {
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

const xqc_scheduler_callback_t xqc_minrtt_scheduler_cb = {
    .xqc_scheduler_size             = xqc_minrtt_scheduler_size,
    .xqc_scheduler_init             = xqc_minrtt_scheduler_init,
    .xqc_scheduler_get_path         = xqc_minrtt_scheduler_get_path,
};