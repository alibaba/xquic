/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/scheduler/xqc_scheduler_minrtt.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"

static size_t
xqc_minrtt_scheduler_size()
{
    return 0;
}

static void
xqc_minrtt_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    return;
}

xqc_path_ctx_t *
xqc_minrtt_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd, int reinject,
    xqc_bool_t *cc_blocked)
{
    xqc_path_perf_class_t path_class;
    xqc_path_ctx_t *best_path[XQC_PATH_CLASS_PERF_CLASS_SIZE] = { NULL };

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_send_ctl_t *send_ctl;

    /* min RTT */
    uint64_t path_srtt = 0;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_bool_t path_can_send = XQC_FALSE;

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

        /* @TODO: It is not correct for BBR/BBRv2, as they do not used cwnd to decide
         *        how much data can be sent in one RTT. But, currently, BBR does not 
         *        work well for MPQUIC due to the problem of applimit. We may adapt this
         *        to BBR in the future, if we manage to fix the applimit problem of BBR. 
         */
        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd);

        if (!path_can_send) {
            goto skip_path;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        path_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        
        if (best_path[path_class] == NULL 
            || path_srtt < best_path[path_class]->path_send_ctl->ctl_srtt)
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

    for (path_class = XQC_PATH_CLASS_AVAILABLE_HIGH; 
         path_class < XQC_PATH_CLASS_PERF_CLASS_SIZE; 
         path_class++)
    {
        if (best_path[path_class] != NULL) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|best path:%ui|frame_type:%s|"
                    "pn:%ui|size:%ud|reinj:%d|path_class:%d|",
                    best_path[path_class]->path_id, 
                    xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
                    packet_out->po_pkt.pkt_num,
                    packet_out->po_used_size, reinject, path_class);
            return best_path[path_class];
        }
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|No available paths to schedule|conn:%p|", conn);
    return NULL;
}

const xqc_scheduler_callback_t xqc_minrtt_scheduler_cb = {
    .xqc_scheduler_size             = xqc_minrtt_scheduler_size,
    .xqc_scheduler_init             = xqc_minrtt_scheduler_init,
    .xqc_scheduler_get_path         = xqc_minrtt_scheduler_get_path,
};