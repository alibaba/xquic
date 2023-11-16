/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/reinjection_control/xqc_reinj_default.h"

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
xqc_default_reinj_ctl_size()
{
    return sizeof(xqc_default_reinj_ctl_t);
}

static void
xqc_default_reinj_ctl_init(void *reinj_ctl, xqc_connection_t *conn)
{
    xqc_default_reinj_ctl_t *rctl = (xqc_default_reinj_ctl_t *)reinj_ctl;

    rctl->log = conn->log;
    rctl->conn = conn;
}

static xqc_bool_t
xqc_default_reinj_can_reinject_after_sched(xqc_default_reinj_ctl_t *rctl, 
    xqc_packet_out_t *po)
{
    xqc_connection_t *conn = rctl->conn;

    if (xqc_list_empty(&conn->conn_send_queue->sndq_send_packets)
        && ((po->po_frame_types & XQC_FRAME_BIT_STREAM) 
            || (po->po_frame_types & XQC_FRAME_BIT_MAX_STREAM_DATA)
            || (po->po_frame_types & XQC_FRAME_BIT_RESET_STREAM)
            || (po->po_frame_types & XQC_FRAME_BIT_STOP_SENDING)
            || (po->po_frame_types & XQC_FRAME_BIT_MAX_STREAMS)
            || (po->po_frame_types & XQC_FRAME_BIT_MAX_DATA)
            || (po->po_frame_types & XQC_FRAME_BIT_DATA_BLOCKED)
            || (po->po_frame_types & XQC_FRAME_BIT_STREAM_DATA_BLOCKED)
            || (po->po_frame_types & XQC_FRAME_BIT_STREAMS_BLOCKED)
            || (po->po_frame_types & XQC_FRAME_BIT_CONNECTION_CLOSE))
        && !(po->po_flag & XQC_POF_NOT_REINJECT)
        && !(XQC_MP_PKT_REINJECTED(po))
        && (po->po_flag & XQC_POF_IN_FLIGHT)) 
    {   
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

static xqc_bool_t
xqc_default_reinj_can_reinject(void *ctl, 
    xqc_packet_out_t *po, xqc_reinjection_mode_t mode)
{
    xqc_bool_t can_reinject = XQC_FALSE;
    xqc_default_reinj_ctl_t *rctl = (xqc_default_reinj_ctl_t*)ctl;

    switch (mode) {
    case XQC_REINJ_UNACK_AFTER_SCHED:
        can_reinject = xqc_default_reinj_can_reinject_after_sched(rctl, po);
        break;
    default:
        can_reinject = XQC_FALSE;
        break;
    }

    return can_reinject;
}



const xqc_reinj_ctl_callback_t xqc_default_reinj_ctl_cb = {
    .xqc_reinj_ctl_size             = xqc_default_reinj_ctl_size,
    .xqc_reinj_ctl_init             = xqc_default_reinj_ctl_init,
    .xqc_reinj_ctl_can_reinject     = xqc_default_reinj_can_reinject,
};