
#include "src/transport/scheduler/xqc_scheduler_ecf_xlink.h"

#include "src/transport/xqc_reinjection.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_wakeup_pq.h"
#include "src/transport/xqc_packet_out.h"

#include "src/common/xqc_common.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str_hash.h"
#include "src/common/xqc_hash.h"
#include "src/common/xqc_priority_q.h"
#include "src/common/xqc_memory_pool.h"
#include "src/common/xqc_random.h"

#include "xquic/xqc_errno.h"

static size_t
xqc_ecf_scheduler_size()
{
    return sizeof(xqc_ecf_scheduler_t);
}

/**
 * @brief Initialize the ECF parameters
 * 
 * @param scheduler 
 * @param log 
 */
static void
xqc_ecf_scheduler_init(void *scheduler, xqc_log_t *log)
{
    xqc_ecf_scheduler_t *ecf = (xqc_ecf_scheduler_t *)(scheduler);
    ecf->waiting = 0;
    ecf->r_beta = 4;
    return;
}

static xqc_bool_t
xqc_path_ecf_schedule_cwnd_test2(xqc_path_ctx_t *path)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint32_t inflight = send_ctl->ctl_bytes_in_flight;
    uint32_t cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    uint32_t queued_bytes = path->path_schedule_bytes;
    if (inflight < cwnd && queued_bytes <= (cwnd - inflight)) {
        return XQC_TRUE;
    }
    return XQC_FALSE;
}

static xqc_bool_t
xqc_path_ecf_schedule_check_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int cwnd_check)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint32_t total_bytes = path->path_schedule_bytes;

    /* check the anti-amplification limit, will allow a bit larger than 3x received */
    if (xqc_send_ctl_check_anti_amplification(send_ctl, total_bytes)) {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_INFO,
                "|blocked by anti amplification limit|total_sent:%ui|3*total_recv:%ui|",
                send_ctl->ctl_bytes_send + total_bytes, 3 * send_ctl->ctl_bytes_recv);
        return XQC_FALSE;
    }

    /* normal packets in send list will be blocked by cc */
    // if (!xqc_send_packet_check_cc(send_ctl, packet_out, total_bytes))
    // {
    //     xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|blocked by cc|", path->path_id);
    //     return XQC_FALSE;
    // }

    /* marked by wh:pkts in path level send queue will also block send */
    if (cwnd_check && !xqc_path_ecf_schedule_cwnd_test2(path)) {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|sendq already fills the cwnd", path->path_id);
        return XQC_FALSE;
    }

    return XQC_TRUE;
}


static  xqc_path_ctx_t *
xqc_ecf_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check, int reinject)
{
    xqc_ecf_scheduler_t *ecf = (xqc_ecf_scheduler_t *)(scheduler);
    xqc_path_ctx_t *min_path = NULL;                       /* overall best (fastest) path */
    xqc_path_ctx_t *best_path = NULL;                      /* current fastest path | slower path */ 
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_send_ctl_t *send_ctl;

    uint64_t cwnd_f = 0;                                   /* fast path cwnd (bytes) */
    uint64_t cwnd_s = 0;                                   /* slow path cwnd (bytes) */
    xqc_usec_t srtt_f = 0;                                 /* fast path srtt */
    xqc_usec_t srtt_s = 0;                                 /* slow path srtt */
    xqc_usec_t rttvar_f = 0;                               /* fast path rttvar */
    xqc_usec_t rttvar_s = 0;                               /* slow path rttvar */

    // uint32_t total_bytes;

    uint64_t min_rtt = XQC_MAX_UINT64_VALUE;
    /* marked by wh: find the overall best (fastest) path */
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }
        if (reinject && (packet_out->po_path_id == path->path_id)) {
            continue;
        }
        /* delete cc send limited check */
        // if (check && (!xqc_path_schedule_ecf_check_can_send(path, packet_out))) {
        //     continue;
        // }
        /* get fastest path */
        if (path->path_send_ctl->ctl_srtt < min_rtt) {
            min_path = path;
            min_rtt = path->path_send_ctl->ctl_srtt;
        }
    }

    // min_path = xqc_xlink_scheduler_get_path()
    uint64_t curr_min_rtt = XQC_MAX_UINT64_VALUE;
    /* marked by wh: find the current best subflow according to the default scheduler */
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        if (reinject && (packet_out->po_path_id == path->path_id)) {
            continue;
        }
        /* add cc send limited check */
        if (check && (!xqc_path_ecf_schedule_check_can_send(path, packet_out, 1))) {
            continue;
        } 

        xqc_log(conn->log, XQC_LOG_DEBUG, "|path srtt|conn:%p|path_id:%ui|path_srtt:%ui|", 
                conn, path->path_id, path->path_send_ctl->ctl_srtt);

        if (path->path_send_ctl->ctl_srtt < curr_min_rtt) {
            best_path = path;
            curr_min_rtt = path->path_send_ctl->ctl_srtt;
        }
    }
    /* marked by wh:best_path->path_id != min_path->path_id */
    if (best_path && min_path && best_path->path_id != min_path->path_id) {

        cwnd_f = min_path->path_send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(min_path->path_send_ctl->ctl_cong);
        cwnd_s = best_path->path_send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(best_path->path_send_ctl->ctl_cong);
        srtt_f = min_path->path_send_ctl->ctl_srtt;
        srtt_s = best_path->path_send_ctl->ctl_srtt;
        rttvar_f = min_path->path_send_ctl->ctl_rttvar;
        rttvar_s = best_path->path_send_ctl->ctl_rttvar;

        xqc_usec_t delta = xqc_max(rttvar_f, rttvar_s);
        // uint64_t k = packet_out->po_used_size;    /* data size need to be scheduled */
        /* consider queue delay: min_path has queued bytes, best_path has no queued bytes */
        uint64_t k = xqc_max(packet_out->po_used_size + min_path->path_schedule_bytes, cwnd_f);
        uint64_t lhs = srtt_f * (k + cwnd_f);
        uint64_t rhs = cwnd_f * (srtt_s + delta);

        if (ecf->r_beta * lhs < ecf->r_beta * rhs + ecf->waiting * rhs) {
            /* when cwnd_s == 0? */
            if (k * srtt_s > (2 * srtt_f + delta) * cwnd_s) {
                ecf->waiting = 1; 
                best_path = NULL;                     /* need to waiting for fast subflow not blocked */
                // printf("debug2\n");
            }
        }
        else {
            ecf->waiting = 0;
        }
        
    }
    if (best_path == NULL) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|No available paths to schedule|conn:%p|", conn);
        // printf("debug2");

    } else {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|best path:%ui|frame_type:%s|",
                best_path->path_id, xqc_frame_type_2_str(packet_out->po_frame_types));
    }
    return best_path;
}

/* marked by wh: register struct */
const xqc_scheduler_callback_t xqc_ecf_scheduler_cb = {
    .xqc_scheduler_size             = xqc_ecf_scheduler_size,
    .xqc_scheduler_init             = xqc_ecf_scheduler_init,
    .xqc_scheduler_get_path         = xqc_ecf_scheduler_get_path,
};