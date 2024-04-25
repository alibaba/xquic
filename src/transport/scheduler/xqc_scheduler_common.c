#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"

xqc_bool_t
xqc_scheduler_check_path_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int check_cwnd)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint32_t schedule_bytes = path->path_schedule_bytes;

    /* normal packets in send list will be blocked by cc */
    if (check_cwnd && (!xqc_send_packet_cwnd_allows(send_ctl, packet_out, schedule_bytes, 0)))
    {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|blocked by cwnd|", path->path_id);
        return XQC_FALSE;
    }

    return XQC_TRUE;
}