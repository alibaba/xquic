/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/reinjection_control/xqc_reinj_xlink.h"

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
xqc_xlink_reinj_ctl_size()
{
    return sizeof(xqc_xlink_reinj_ctl_t);
}

static void
xqc_xlink_reinj_ctl_init(void *reinj_ctl, const xqc_conn_settings_t *settings, xqc_log_t *log)
{
    xqc_xlink_reinj_ctl_t *xlink = (xqc_xlink_reinj_ctl_t *)reinj_ctl;

    xlink->log = log;
}


static xqc_bool_t
xqc_xlink_reinj_ctl_lost_queue(void *reinj_ctl, void *qoe_ctx, xqc_connection_t *conn)
{
    if(!conn->conn_settings.mp_enable_reinjection) {
        return XQC_FALSE;
    }

    if (conn->active_path_count < 2) {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}


static xqc_bool_t
xqc_xlink_reinj_ctl_unack_queue(void *reinj_ctl, void *qoe_ctx, xqc_connection_t *conn)
{
    if(!conn->conn_settings.mp_enable_reinjection) {
        return XQC_FALSE;
    }

    if (conn->active_path_count < 2) {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}


const xqc_reinj_ctl_callback_t xqc_xlink_reinj_ctl_cb = {
    .xqc_reinj_ctl_size             = xqc_xlink_reinj_ctl_size,
    .xqc_reinj_ctl_init             = xqc_xlink_reinj_ctl_init,
    .xqc_reinj_ctl_lost_queue       = xqc_xlink_reinj_ctl_lost_queue,
    .xqc_reinj_ctl_unack_queue      = xqc_xlink_reinj_ctl_unack_queue,
};