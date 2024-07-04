/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/reinjection_control/xqc_reinj_deadline.h"

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
xqc_deadline_reinj_ctl_size()
{
    return sizeof(xqc_deadline_reinj_ctl_t);
}

static void
xqc_deadline_reinj_ctl_init(void *reinj_ctl, xqc_connection_t *conn)
{
    xqc_deadline_reinj_ctl_t *rctl = (xqc_deadline_reinj_ctl_t *)reinj_ctl;

    rctl->log = conn->log;
    rctl->conn = conn;
}

static inline xqc_bool_t
xqc_deadline_reinj_check_packet(xqc_packet_out_t *po)
{
    if (((po->po_frame_types & XQC_FRAME_BIT_STREAM) 
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
xqc_deadline_reinj_can_reinject_before_sched(xqc_deadline_reinj_ctl_t *rctl, 
    xqc_packet_out_t *po)
{
    if (!xqc_deadline_reinj_check_packet(po)) {
        return XQC_FALSE;
    }

    xqc_connection_t *conn = rctl->conn;
    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t min_srtt = xqc_conn_get_min_srtt(conn, 0);

    double   factor      = conn->conn_settings.reinj_flexible_deadline_srtt_factor;
    double   flexible    = factor * min_srtt;
    uint64_t hard        = conn->conn_settings.reinj_hard_deadline;
    uint64_t lower_bound = conn->conn_settings.reinj_deadline_lower_bound;
    double   deadline    = xqc_max(xqc_min(flexible, (double)hard), (double)lower_bound);

    xqc_log(conn->log, XQC_LOG_DEBUG, 
            "|deadline:%f|factor:%.4f|min_srtt:%ui|flexible:%f|hard:%ui|"
            "lower_bound:%ui|now:%ui|sent_time:%ui|frame:%s|",
            deadline, factor, min_srtt, flexible, hard, 
            lower_bound, now, po->po_sent_time, 
            xqc_frame_type_2_str(conn->engine, po->po_frame_types));

    if ((double)(now - po->po_sent_time) >= deadline) {   
        return XQC_TRUE;
    }

    return XQC_FALSE;
}


static xqc_bool_t
xqc_deadline_reinj_can_reinject_after_send(xqc_deadline_reinj_ctl_t *rctl, 
    xqc_packet_out_t *po)
{
    if (!xqc_deadline_reinj_check_packet(po)) {
        return XQC_FALSE;
    }

    xqc_connection_t *conn = rctl->conn;
    xqc_path_ctx_t *path = NULL;
    xqc_path_perf_class_t path_class;

    path = xqc_conn_find_path_by_path_id(conn, po->po_path_id);
    
    if (path) {
        path_class = xqc_path_get_perf_class(path);
        if (path_class == XQC_PATH_CLASS_STANDBY_LOW 
            || path_class == XQC_PATH_CLASS_AVAILABLE_LOW)
        {
            return XQC_TRUE;
        }
    }
    
    return XQC_FALSE;
}

static xqc_bool_t
xqc_deadline_reinj_can_reinject(void *ctl, 
    xqc_packet_out_t *po, xqc_reinjection_mode_t mode)
{
    xqc_bool_t can_reinject = XQC_FALSE;
    xqc_deadline_reinj_ctl_t *rctl = (xqc_deadline_reinj_ctl_t*)ctl;

    switch (mode) {
    case XQC_REINJ_UNACK_BEFORE_SCHED:
        can_reinject = xqc_deadline_reinj_can_reinject_before_sched(rctl, po);
        break;
    case XQC_REINJ_UNACK_AFTER_SEND:
        can_reinject = xqc_deadline_reinj_can_reinject_after_send(rctl, po);
        break;
    default:
        can_reinject = XQC_FALSE;
        break;
    }

    return can_reinject;
}


const xqc_reinj_ctl_callback_t xqc_deadline_reinj_ctl_cb = {
    .xqc_reinj_ctl_size             = xqc_deadline_reinj_ctl_size,
    .xqc_reinj_ctl_init             = xqc_deadline_reinj_ctl_init,
    .xqc_reinj_ctl_can_reinject     = xqc_deadline_reinj_can_reinject,
};