#include "src/transport/scheduler/xqc_scheduler_otias_xlink.h"

#include "src/transport/xqc_send_ctl.h"


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

    /* normal packets in send list will be blocked by cc */
    if (!xqc_path_otias_schedule_cwnd_test2(path)) {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|sendq already fills the cwnd", path->path_id);
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

/**
 * @brief Check out if it is allowed to reinject this packet on path
 * 
 * @param path The target path
 * @param packet_out Packet that need to be reinjected
 * @return xqc_bool_t 
 */
static xqc_bool_t
xqc_path_dont_reinject_packet(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    if (packet_out && packet_out->po_path_id == path->path_id) {
        return XQC_TRUE;
    }
    return XQC_FALSE;
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
    uint64_t best_metric = XQC_MAX_UINT64_VALUE;
    uint64_t metric;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_path_ctx_t *best_path = NULL;
    xqc_path_ctx_t *backup_path = NULL;                     /* backup path */ 
    uint64_t backup_metric = XQC_MAX_UINT64_VALUE;          /* backup path's metric */
    xqc_bool_t cwnd_has_space;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {

        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        cwnd_has_space = xqc_path_otias_schedule_cwnd_test2(path);
        metric = xqc_otias_scheduler_calc_metric(path);

        if (reinject && xqc_path_dont_reinject_packet(path, packet_out)) {
            if (!backup_path || metric < backup_metric) {
                if (cwnd_has_space) {
                    backup_metric = metric;
                    backup_path = path;
                }
            }
        }
        else {
            if (!best_path || metric < best_metric) {
                if (!(packet_out->po_flag & XQC_POF_RETRANSED) || cwnd_has_space) {
                    best_metric = metric;
                    best_path = path;
                }
            }
        }
    }

    if (!best_path) {
        if (backup_path) {
            best_path = backup_path;
        }
    }

    if (!best_path) {
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