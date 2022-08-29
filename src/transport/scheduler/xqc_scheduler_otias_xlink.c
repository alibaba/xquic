#include "src/transport/scheduler/xqc_scheduler_otias_xlink.h"

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

#include "xqc_scheduler_otias_xlink.h"

static size_t
xqc_otias_scheduler_size()
{
    return 0;
}

static void
xqc_otias_scheduler_init(void *scheduler, xqc_log_t *log)
{
    return;
}

static xqc_bool_t
xqc_path_otias_schedule_cwnd_test1(xqc_path_ctx_t *path)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint32_t inflight = send_ctl->ctl_bytes_in_flight;
    uint32_t cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    if (inflight < cwnd) {
        return XQC_TRUE;
    }
    return XQC_FALSE;
}

static xqc_bool_t
xqc_path_otias_schedule_cwnd_test2(xqc_path_ctx_t *path)
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
xqc_path_otias_schedule_check_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
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

    // /* normal packets in send list will be blocked by cc */
    // if (!xqc_send_packet_check_cc(send_ctl, packet_out, total_bytes))
    // {
    //     xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|blocked by cc|", path->path_id);
    //     return XQC_FALSE;
    // }

    /* marked by wh:pkts in path level send queue will also block send */
    // uint32_t inflight = send_ctl->ctl_bytes_in_flight;
    // uint32_t cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    if (!xqc_path_otias_schedule_cwnd_test2(path)) {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|sendq already fills the cwnd", path->path_id);
        return XQC_FALSE;
    }

    return XQC_TRUE;
}


/**
 * @brief calculate the metric of a path
 * 
 * @param path path to be calculated
 * @return uint32_t the metric
 */
static uint64_t
xqc_otias_scheduler_calc_metric(xqc_path_ctx_t *path)
{
    uint64_t cwnd_now = path->path_send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(path->path_send_ctl->ctl_cong);
    uint64_t inflight_now = path->path_send_ctl->ctl_bytes_in_flight;
    xqc_usec_t srtt = path->path_send_ctl->ctl_srtt;
    uint64_t not_yet_sent = path->path_schedule_bytes;                                                                   /* marked by wh:queued bytes in one path */
    uint64_t bytes_num_can_be_sent = cwnd_now - inflight_now;
    uint64_t wait, metric;

    if (not_yet_sent < bytes_num_can_be_sent) {
        wait = 0;
    }
    else {
        if (cwnd_now < XQC_QUIC_MSS) {
            cwnd_now = XQC_QUIC_MSS;
        }
        uint64_t num = not_yet_sent - bytes_num_can_be_sent + XQC_QUIC_MSS;
        uint64_t rtts_wait = num / cwnd_now;
        wait = rtts_wait * srtt;
    }
    metric = wait + srtt / 2;

    return metric;
}

static xqc_path_ctx_t *
xqc_otias_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check, int reinject)
{
    uint64_t min_T = XQC_MAX_UINT64_VALUE;
    uint64_t metric;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_path_ctx_t *best_path = NULL;
    xqc_path_ctx_t *backup_path = NULL;       /* backup path */ 
    uint64_t backup_metric;                   /* backup path's metric */
    xqc_bool_t blocked;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (reinject && (packet_out->po_path_id == path->path_id)) {
            continue;
        }
        blocked = xqc_path_otias_schedule_cwnd_test2(path);
        metric = xqc_otias_scheduler_calc_metric(path);
        if (metric < min_T) {
            min_T = metric;
            best_path = path;
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

const xqc_scheduler_callback_t xqc_otias_scheduler_cb = {
    .xqc_scheduler_size             = xqc_otias_scheduler_size,
    .xqc_scheduler_init             = xqc_otias_scheduler_init,
    .xqc_scheduler_get_path         = xqc_otias_scheduler_get_path,
};