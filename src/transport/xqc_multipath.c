/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_wakeup_pq.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_reinjection.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_datagram.h"

#include "src/common/xqc_common.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str_hash.h"
#include "src/common/xqc_hash.h"
#include "src/common/xqc_priority_q.h"
#include "src/common/xqc_memory_pool.h"
#include "src/common/xqc_random.h"

#include "xquic/xqc_errno.h"

#include "src/http3/xqc_h3_conn.h" /* TODO:delete me */

#include <math.h>

void
xqc_path_schedule_buf_destroy(xqc_path_ctx_t *path)
{
    for (xqc_send_type_t type = 0; type < XQC_SEND_TYPE_N; type++) {
        xqc_send_queue_destroy_packets_list(&path->path_schedule_buf[type]);
    }

    path->path_schedule_bytes = 0;
}

void
xqc_path_schedule_buf_pre_destroy(xqc_send_queue_t *send_queue, xqc_path_ctx_t *path)
{
    for (xqc_send_type_t type = 0; type < XQC_SEND_TYPE_N; type++) {
        xqc_send_queue_pre_destroy_packets_list(send_queue, &path->path_schedule_buf[type]);
    }

    path->path_schedule_bytes = 0;
}

void 
xqc_path_destroy(xqc_path_ctx_t *path)
{
    if (path == NULL) {
        return;
    }

    if (path->path_send_ctl != NULL) {
        xqc_send_ctl_destroy(path->path_send_ctl);
        path->path_send_ctl = NULL;
    }

    if (path->path_pn_ctl != NULL) {
        xqc_pn_ctl_destroy(path->path_pn_ctl);
        path->path_pn_ctl = NULL;
    }

    xqc_path_schedule_buf_destroy(path);
 
    xqc_free((void *)path);
}

xqc_path_ctx_t *
xqc_path_create(xqc_connection_t *conn, xqc_cid_t *scid, xqc_cid_t *dcid)
{
    xqc_path_ctx_t *path = NULL;

    path = xqc_calloc(1, sizeof(xqc_path_ctx_t));
    if (path == NULL) {
        return NULL;
    }
    xqc_memzero(path, sizeof(xqc_path_ctx_t));

    path->path_state = XQC_PATH_STATE_INIT;
    path->parent_conn = conn;

    path->tra_path_status = XQC_TRA_PATH_STATUS_IN_USE;
    path->app_path_status = XQC_APP_PATH_STATUS_AVAILABLE;
    path->app_path_status_send_seq_num = 0;
    path->app_path_status_recv_seq_num = 0;

    path->path_pn_ctl = xqc_pn_ctl_create(conn);
    if (path->path_pn_ctl == NULL) {
        goto err;
    }

    path->path_send_ctl = xqc_send_ctl_create(path);
    if (path->path_send_ctl == NULL) {
        goto err;
    }

    for (xqc_send_type_t type = 0; type < XQC_SEND_TYPE_N; type++) {
        xqc_init_list_head(&path->path_schedule_buf[type]);
    }
    xqc_init_list_head(&path->path_reinj_tmp_buf);

    /* cid & path_id init */

    if (scid == NULL) {
        if (xqc_get_unused_cid(&conn->scid_set.cid_set, &path->path_scid) != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|conn don't have available scid|");
            goto err;
        }

    } else {
        /* already have scid */
        xqc_cid_inner_t *inner_cid = xqc_cid_in_cid_set(&conn->scid_set.cid_set, scid);
        if (inner_cid == NULL) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|invalid scid:%s|", xqc_scid_str(scid));
            goto err;
        }

        xqc_cid_copy(&path->path_scid, &inner_cid->cid);
    }

    if (dcid == NULL) {
        if (xqc_get_unused_cid(&(conn->dcid_set.cid_set), &(path->path_dcid)) != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|MP|conn don't have available dcid|");
            goto err;
        }

    } else {
        /* already have dcid */
        xqc_cid_copy(&(path->path_dcid), dcid);
    }

    path->path_id = path->path_scid.cid_seq_num;
    path->path_create_time = xqc_monotonic_timestamp();
    path->curr_pkt_out_size = conn->pkt_out_size;
    path->path_max_pkt_out_size = conn->max_pkt_out_size;

    /* insert path to conn_paths_list */
    xqc_list_add_tail(&path->path_list, &conn->conn_paths_list);
    conn->create_path_count++;

    xqc_log(conn->engine->log, XQC_LOG_DEBUG, "|path:%ui|dcid:%s|scid:%s|create_path_count:%ud|",
            path->path_id, xqc_dcid_str(&path->path_dcid), xqc_scid_str(&path->path_scid), conn->create_path_count);

    return path;

err:
    xqc_path_destroy(path);
    return NULL;
}

xqc_int_t
xqc_generate_path_challenge_data(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    xqc_engine_t *engine = conn->engine;

    return xqc_get_random(engine->rand_generator,
                          path->path_challenge_data, XQC_PATH_CHALLENGE_DATA_LEN);
}

xqc_int_t
xqc_path_init(xqc_path_ctx_t *path, xqc_connection_t *conn)
{
    xqc_int_t ret = XQC_ERROR;

    if (conn->peer_addrlen > 0) {
        xqc_memcpy(path->peer_addr, conn->peer_addr, conn->peer_addrlen);
        path->peer_addrlen = conn->peer_addrlen;
    }

    if (conn->local_addrlen > 0) {
        xqc_memcpy(path->local_addr, conn->local_addr, conn->local_addrlen);
        path->local_addrlen = conn->local_addrlen;
    }


    if (path->path_id == XQC_INITIAL_PATH_ID) {
        xqc_set_path_state(path, XQC_PATH_STATE_ACTIVE);
        conn->validated_path_count++;

    } else {
        /* generate random data for path challenge, store it to validate path_response */
        ret = xqc_generate_path_challenge_data(conn, path);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_generate_path_challenge_data error|%d|", ret);
            return ret;
        }

        /* write path challenge frame & send immediately */
        ret = xqc_write_path_challenge_frame_to_packet(conn, path);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_path_challenge_frame_to_packet error|%d|", ret);
            return ret;
        }

        xqc_set_path_state(path, XQC_PATH_STATE_VALIDATING);
    }

    xqc_log(conn->engine->log, XQC_LOG_DEBUG, "|path:%ui|dcid:%s|scid:%s|state:%d|",
            path->path_id, xqc_dcid_str(&path->path_dcid), xqc_scid_str(&path->path_scid), path->path_state);

    return XQC_OK;
}



/* Traverse unack packets queue and move them to loss packets queue for retransmission */
void
xqc_path_move_unack_packets_from_conn(xqc_path_ctx_t *path, xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *po = NULL;
    uint64_t closing_path_id = path->path_id;
    xqc_int_t repair_dgram = 0;

    xqc_list_for_each_safe(pos, next, &conn->conn_send_queue->sndq_unacked_packets[XQC_PNS_APP_DATA]) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        repair_dgram = 0;

        if (xqc_send_ctl_indirectly_ack_or_drop_po(conn, po)) {
            continue;
        }

        if (po->po_path_id == closing_path_id) {
            if (po->po_flag & XQC_POF_IN_FLIGHT) {
                xqc_send_ctl_decrease_inflight(conn, po);

                if (po->po_frame_types & XQC_FRAME_BIT_DATAGRAM) {
                    path->path_send_ctl->ctl_lost_dgram_cnt++;
                    repair_dgram = xqc_datagram_notify_loss(conn, po);
                    if (conn->conn_settings.datagram_force_retrans_on) {
                        repair_dgram = XQC_DGRAM_RETX_ASKED_BY_APP;
                    }
                }
                
                if (XQC_NEED_REPAIR(po->po_frame_types) 
                    || repair_dgram == XQC_DGRAM_RETX_ASKED_BY_APP) 
                {
                    xqc_send_queue_copy_to_lost(po, conn->conn_send_queue);

                } else {
                    /* for datagram, we should remove all copies in the unacked list */
                    if (po->po_frame_types & XQC_FRAME_BIT_DATAGRAM) {
                        xqc_send_ctl_on_dgram_dropped(conn, po);
                        xqc_send_queue_maybe_remove_unacked(po, conn->conn_send_queue, NULL);

                    } else {
                        /* if a packet don't need to be repair, don't retransmit it */
                        xqc_send_queue_remove_unacked(po, conn->conn_send_queue);
                        xqc_send_queue_insert_free(po, &conn->conn_send_queue->sndq_free_packets, conn->conn_send_queue);
                    }
                }
            }
        }
    }
}

void
xqc_set_path_state(xqc_path_ctx_t *path, xqc_path_state_t dst_state)
{
    xqc_connection_t *conn = path->parent_conn;

    if (path->path_state == dst_state) {
        return;
    }

    if (path->path_state == XQC_PATH_STATE_ACTIVE) {
        conn->active_path_count--;
        
        if (path->tra_path_status == XQC_TRA_PATH_STATUS_IN_USE) {
            conn->in_use_active_path_count--;
        }

    } else if (dst_state == XQC_PATH_STATE_ACTIVE) {
        conn->active_path_count++;

        if (path->tra_path_status == XQC_TRA_PATH_STATUS_IN_USE) {
            conn->in_use_active_path_count++;
        }
    }

    path->path_state = dst_state;
}

xqc_int_t
xqc_path_immediate_close(xqc_path_ctx_t *path)
{
    if (path->path_state >= XQC_PATH_STATE_CLOSING) {
        return XQC_OK;
    }

    xqc_connection_t *conn = path->parent_conn;
    xqc_int_t ret = XQC_OK;
    
    ret = xqc_write_path_abandon_frame_to_packet(conn, path);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_path_abandon_frame_to_packet error|ret:%d|", ret);
    }

    xqc_set_path_state(path, XQC_PATH_STATE_CLOSING);

    /* 将已经在该路径发送的 unack packets 移到 lost queue 进行重传 */
    xqc_path_move_unack_packets_from_conn(path, conn);

    for (xqc_send_type_t type = 0; type < XQC_SEND_TYPE_N; type++) {
        /* 将已经分配到该路径但还未发送的包 放回原路径级别队列进行重新分配 (区分 lost/pto/send) */
        xqc_path_send_buffer_clear(conn, path, NULL, type);
    }
    
    /* try to update MSS */
    if (conn->conn_settings.enable_pmtud) {
        xqc_conn_try_to_update_mss(conn);
    }

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t pto = xqc_conn_get_max_pto(conn);
    if (!xqc_timer_is_set(&path->path_send_ctl->path_timer_manager, XQC_TIMER_PATH_DRAINING)) {
        xqc_timer_set(&path->path_send_ctl->path_timer_manager, XQC_TIMER_PATH_DRAINING, now, 3 * pto);
    }

    return XQC_OK;
}

xqc_int_t
xqc_path_closed(xqc_path_ctx_t *path)
{
    if ((path == NULL) || (path->path_state == XQC_PATH_STATE_CLOSED)) {
        return XQC_OK;
    }

    xqc_connection_t *conn = path->parent_conn;

    xqc_set_path_state(path, XQC_PATH_STATE_CLOSED);
    xqc_log(conn->log, XQC_LOG_INFO, "|path closed|path:%ui|", path->path_id);

    for (int i = 0; i <= XQC_TIMER_PATH_DRAINING; i++) {
        xqc_timer_unset(&path->path_send_ctl->path_timer_manager, i);
    }

    /* remove path notify */
    if (conn->transport_cbs.path_removed_notify) {
        conn->transport_cbs.path_removed_notify(&conn->scid_set.user_scid, path->path_id,
                                                xqc_conn_get_user_data(conn));
    }

    /* TODO: releadse path recource */
    return XQC_OK;
}

/**
 * Check whether the connection supports multi-path or not.
 * @param conn  connection context
 * @return enable_multipath 0:not support, 1:MPNS
 */
xqc_multipath_mode_t
xqc_conn_enable_multipath(xqc_connection_t *conn)
{
    if ((conn->local_settings.enable_multipath == 1)
        && (conn->remote_settings.enable_multipath == 1))
    {
        if (conn->dcid_set.current_dcid.cid_len == 0
            || conn->scid_set.user_scid.cid_len == 0) 
        {
            xqc_log(conn->log, XQC_LOG_ERROR, 
                    "|mutlipath is not possible for connections"
                    " with zero-length DCID|");
            XQC_CONN_ERR(conn, TRA_TRANSPORT_PARAMETER_ERROR);
            return XQC_CONN_NOT_SUPPORT_MULTIPATH;
        }
        return XQC_CONN_MULTIPATH_MULTIPLE_PNS;
    }

    return XQC_CONN_NOT_SUPPORT_MULTIPATH;

}


xqc_int_t
xqc_conn_create_path(xqc_engine_t *engine, const xqc_cid_t *scid, uint64_t *new_path_id)
{
    xqc_connection_t *conn = NULL;
    xqc_path_ctx_t *path = NULL;

    conn = xqc_engine_conns_hash_find(engine, scid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return -XQC_ECONN_NFOUND;
    }
    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return -XQC_CLOSING;
    }

    /* check mp-support */
    if (!conn->enable_multipath) {
        xqc_log(conn->log, XQC_LOG_WARN,
                "|Multipath is not supported in remote host, use the first path as default!|");
        return -XQC_EMP_NOT_SUPPORT_MP;
    }

    /* must have at least one available unused scid & dcid */
    if (xqc_conn_check_unused_cids(conn) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_WARN,
                "|don't have available cid for new path|");
        return -XQC_EMP_NO_AVAIL_PATH_ID;
    }

    path = xqc_conn_create_path_inner(conn, NULL, NULL);
    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_path_create error|");
        return -XQC_EMP_CREATE_PATH;
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    *new_path_id = path->path_id;

    return XQC_OK;
}

xqc_int_t
xqc_conn_close_path(xqc_engine_t *engine, const xqc_cid_t *scid, uint64_t closed_path_id)
{
    xqc_connection_t *conn = NULL;
    xqc_path_ctx_t *path = NULL;

    conn = xqc_engine_conns_hash_find(engine, scid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return -XQC_ECONN_NFOUND;
    }
    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return -XQC_CLOSING;
    }

    /* check mp-support */
    if (!conn->enable_multipath) {
        xqc_log(engine->log, XQC_LOG_WARN,
                "|Multipath is not supported in connection|%p|", conn);
        return -XQC_EMP_NOT_SUPPORT_MP;
    }

    /* abandon path */
    path = xqc_conn_find_path_by_path_id(conn, closed_path_id);
    if (path == NULL) {
        xqc_log(engine->log, XQC_LOG_WARN,
                "|path is not found by path_id in connection|%p|%ui|", 
                conn, closed_path_id);
        return -XQC_EMP_PATH_NOT_FOUND;
    }

    /* don't close the only active path */
    if (conn->active_path_count < 2 && path->path_state == XQC_PATH_STATE_ACTIVE) {
        xqc_log(engine->log, XQC_LOG_WARN,
                "|abandon the only active path in connection|%p|%ui|", 
                conn, closed_path_id);
        return -XQC_EMP_NO_ACTIVE_PATH;
    }

    xqc_int_t ret = xqc_path_immediate_close(path);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_path_immediate_close error|%d|", ret);
        return ret;
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    xqc_engine_main_logic_internal(engine);

    return XQC_OK;
}

xqc_int_t
xqc_conn_init_paths_list(xqc_connection_t *conn)
{
    xqc_init_list_head(&conn->conn_paths_list);

    conn->conn_initial_path = xqc_conn_create_path_inner(conn,
                                                         &conn->scid_set.user_scid,
                                                         &conn->dcid_set.current_dcid);
    if (conn->conn_initial_path == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_create_path_inner fail|");
        return -XQC_EMP_CREATE_PATH;
    }

    return XQC_OK;
}

void
xqc_conn_destroy_paths_list(xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_path_destroy(path);
    }
}

xqc_path_ctx_t *
xqc_conn_find_path_by_dcid_seq(xqc_connection_t *conn, uint64_t dcid_seq_num)
{
    xqc_path_ctx_t *path = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_dcid.cid_seq_num == dcid_seq_num) {
            return path;
        }
    }

    return NULL;
}


xqc_path_ctx_t *
xqc_conn_find_path_by_path_id(xqc_connection_t *conn, uint64_t path_id)
{
    xqc_path_ctx_t *path = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_id == path_id) {
            return path;
        }
    }

    return NULL;
}

xqc_path_ctx_t *
xqc_conn_find_path_by_scid(xqc_connection_t *conn, xqc_cid_t *scid)
{
    xqc_path_ctx_t *path = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (xqc_cid_is_equal(&path->path_scid, scid) == XQC_OK) {
            return path;
        }
    }

    if (xqc_cid_is_equal(&conn->original_dcid, scid) == XQC_OK) {
        return conn->conn_initial_path;
    }

    return NULL;
}

xqc_path_ctx_t *
xqc_conn_find_path_by_dcid(xqc_connection_t *conn, xqc_cid_t *dcid)
{
    xqc_path_ctx_t *path = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (xqc_cid_is_equal(&path->path_dcid, dcid) == XQC_OK) {
            return path;
        }
    }

    return NULL;
}



xqc_path_ctx_t *
xqc_conn_create_path_inner(xqc_connection_t *conn,
    xqc_cid_t *scid, xqc_cid_t *dcid)
{
    xqc_int_t ret = XQC_ERROR;
    xqc_path_ctx_t *path = NULL;

    path = xqc_path_create(conn, scid, dcid);
    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_path_create error|");
        return NULL;
    }

    ret = xqc_path_init(path, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_path_init error|%d|", ret);
        return NULL;
    }

    return path;
}


void
xqc_conn_path_metrics_print(xqc_connection_t *conn, xqc_conn_stats_t *stats)
{
    stats->enable_multipath = conn->enable_multipath;

    if (conn->create_path_count > 1) {
        stats->mp_state = (conn->validated_path_count > 1) ? 1 : 2;
    }

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path = NULL;
    int paths_num = 0;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state >= XQC_PATH_STATE_VALIDATING && paths_num < XQC_MAX_PATHS_COUNT) {

            if (path == NULL || path->path_send_ctl == NULL) {
                continue;
            }

            if (path->path_send_ctl->ctl_recv_count == 0) {
                continue;
            }

            stats->paths_info[paths_num].path_id = path->path_id;
            stats->paths_info[paths_num].path_pkt_recv_count = path->path_send_ctl->ctl_recv_count;
            stats->paths_info[paths_num].path_pkt_send_count = path->path_send_ctl->ctl_send_count;

            paths_num++;
        }
    }
}



void
xqc_request_path_metrics_print(xqc_connection_t *conn, xqc_h3_stream_t *h3_stream, xqc_request_stats_t *stats)
{
    stats->mp_default_path_send_weight = 1.0;
    stats->mp_default_path_recv_weight = 1.0;

    stats->mp_standby_path_send_weight = 0.0;
    stats->mp_standby_path_recv_weight = 0.0;

    if (!conn->enable_multipath) {
        return;
    }

    if (conn->active_path_count < 2) {
        return;
    }

    int available_path_cnt = 0, standby_path_cnt = 0;

    uint64_t aggregate_send_bytes = 0, aggregate_recv_bytes = 0;
    uint64_t standby_path_send_bytes = 0, standby_path_recv_bytes = 0;

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_id < XQC_MAX_PATHS_COUNT
            && path->path_id == h3_stream->paths_info[path->path_id].path_id)
        {
            uint64_t send_bytes = h3_stream->paths_info[path->path_id].path_send_bytes;
            uint64_t recv_bytes = h3_stream->paths_info[path->path_id].path_recv_bytes;

            if (send_bytes > 0 || recv_bytes > 0) {
                aggregate_send_bytes += send_bytes;
                aggregate_recv_bytes += recv_bytes;

                if (path->app_path_status == XQC_APP_PATH_STATUS_STANDBY) {
                    standby_path_cnt++;
                    standby_path_send_bytes += send_bytes;
                    standby_path_recv_bytes += recv_bytes;
                } else {
                    available_path_cnt++;
                }
            }
        }
    }

    if ((available_path_cnt > 0) && (standby_path_cnt > 0)) {
        stats->mp_state = 1;

    } else if ((available_path_cnt == 0) && (standby_path_cnt > 0)) {
        stats->mp_state = 2;

    } else if ((available_path_cnt > 0) && (standby_path_cnt == 0)) {
        stats->mp_state = 3;
    }

    if (aggregate_send_bytes != 0) {
        stats->mp_default_path_send_weight = (float)(h3_stream->paths_info[XQC_INITIAL_PATH_ID].path_send_bytes) / aggregate_send_bytes;
        stats->mp_standby_path_send_weight = (float)(standby_path_send_bytes) / aggregate_send_bytes;
    }

    if (aggregate_recv_bytes != 0) {
        stats->mp_default_path_recv_weight = (float)(h3_stream->paths_info[XQC_INITIAL_PATH_ID].path_recv_bytes) / aggregate_recv_bytes;
        stats->mp_standby_path_recv_weight = (float)(standby_path_recv_bytes) / aggregate_recv_bytes;
    }
}

void
xqc_stream_path_metrics_print(xqc_connection_t *conn, xqc_stream_t *stream, char *buff, size_t buff_size)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;

    if (!conn->enable_multipath) {
        snprintf(buff, buff_size, "mp is not supported in connection scid:%s", 
                                  xqc_scid_str(&conn->scid_set.user_scid));
        return;
    }

    uint64_t cwnd = 0, bw = 0;
    xqc_send_ctl_t *send_ctl;

    size_t cursor = 0, ret = 0;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_state >= XQC_PATH_STATE_VALIDATING) {

            /* check buffer size */
            if (cursor + 100 >= buff_size) {
                break;
            }

            if (path->path_id >= XQC_MAX_PATHS_COUNT) {
                continue;
            }

            send_ctl = path->path_send_ctl;

            cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);

            if (send_ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr) {
                bw = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_bandwidth_estimate(send_ctl->ctl_cong);

            } else {
                bw = 0;
            }

            ret = snprintf(buff + cursor, buff_size - cursor, 
                           "#%"PRIu64"-%d-%"PRIu64"-%"PRIu64"-%"PRIu32"-%"PRIu64"-%.4f-%.4f-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64,
                           path->path_id, path->path_state,
                           cwnd, bw, send_ctl->ctl_bytes_in_flight,
                           xqc_send_ctl_get_srtt(send_ctl),
                           xqc_send_ctl_get_retrans_rate(send_ctl),
                           xqc_send_ctl_get_spurious_loss_rate(send_ctl),
                           stream->paths_info[path->path_id].path_pkt_send_count,
                           stream->paths_info[path->path_id].path_pkt_recv_count,
                           stream->paths_info[path->path_id].path_send_bytes,
                           stream->paths_info[path->path_id].path_send_reinject_bytes,
                           stream->paths_info[path->path_id].path_recv_bytes,
                           stream->paths_info[path->path_id].path_recv_reinject_bytes,
                           stream->paths_info[path->path_id].path_recv_effective_bytes,
                           stream->paths_info[path->path_id].path_recv_effective_reinject_bytes);
            cursor += ret;
        }
    }
}

void
xqc_stream_path_metrics_on_send(xqc_connection_t *conn, xqc_packet_out_t *po)
{
    for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
        if (po->po_stream_frames[i].ps_is_used == 1) {
            xqc_stream_t * stream = xqc_find_stream_by_id(po->po_stream_frames[i].ps_stream_id, conn->streams_hash);

            if (stream != NULL && po->po_path_id < XQC_MAX_PATHS_COUNT) {
                stream->paths_info[po->po_path_id].path_id = po->po_path_id;
                stream->paths_info[po->po_path_id].path_pkt_send_count += 1;
                stream->paths_info[po->po_path_id].path_send_bytes += po->po_used_size;

                if (po->po_flag & XQC_POF_REINJECTED_REPLICA) {
                    stream->paths_info[po->po_path_id].path_send_reinject_bytes += po->po_used_size;
                }
            }
        }
    }
}

void
xqc_stream_path_metrics_on_recv(xqc_connection_t *conn, xqc_stream_t *stream, xqc_packet_in_t *pi)
{
    if (pi->pi_path_id < XQC_MAX_PATHS_COUNT) {
        stream->paths_info[pi->pi_path_id].path_id = pi->pi_path_id;
        stream->paths_info[pi->pi_path_id].path_pkt_recv_count += 1;
    }
}


void
xqc_path_metrics_print(xqc_connection_t *conn, char *buff, unsigned buff_size)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;

    int cursor = 0;
    int ret = 0;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state >= XQC_PATH_STATE_VALIDATING) {
            if (cursor >= (buff_size - 100)) {  // enough space
                break;
            }

            // TODO 关于数据抓取说明
            ret = snprintf(buff + cursor, buff_size - cursor,
                           "#%"PRIu64"-%d-%d-%"PRIu64"-%.4f-%"PRIu32"-%"PRIu32"-%"PRIu32"-%"PRIu32"-%"PRIu32""
                           "-%"PRIu32"-%"PRIu32"-%"PRIu32"-%"PRIu64"-%"PRIu64"-%"PRIu32"-%"PRIu32"-%"PRIu32,
                           path->path_id,
                           path->path_state,
                           path->app_path_status,
                           xqc_send_ctl_get_srtt(path->path_send_ctl),
                           xqc_send_ctl_get_retrans_rate(path->path_send_ctl),
                           path->path_send_ctl->ctl_send_count,
                           path->path_send_ctl->ctl_lost_count,
                           path->path_send_ctl->ctl_tlp_count,
                           path->path_send_ctl->ctl_spurious_loss_count,
                           path->path_send_ctl->ctl_recv_count,
                           path->path_send_ctl->ctl_update_latest_rtt_count,
                           path->rebinding_count,
                           path->rebinding_valid,
                           path->path_send_ctl->ctl_bytes_send,
                           path->path_send_ctl->ctl_bytes_recv,
                           path->standby_probe_count,
                           path->app_path_status_changed_count,
                           path->tra_path_status_changed_count);

            cursor += ret;
        }
    }
}

void
xqc_h3s_path_metrics_print(xqc_h3_stream_t *h3_stream, char *buff, unsigned buff_size)
{
    int cursor = 0;
    int ret = 0;

    for (int i = 0; i < XQC_MAX_PATHS_COUNT; ++i) {

        if (h3_stream->paths_info[i].path_id == XQC_MAX_UINT64_VALUE) {
            continue;
        }

        if (cursor >= (buff_size - 100)) {  // enough space
            break;
        }

        ret = snprintf(buff + cursor, buff_size - cursor,
                        "#%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64,
                        h3_stream->paths_info[i].path_id,
                        h3_stream->paths_info[i].path_pkt_send_count,
                        h3_stream->paths_info[i].path_pkt_recv_count,
                        h3_stream->paths_info[i].path_send_bytes,
                        h3_stream->paths_info[i].path_send_reinject_bytes);

        cursor += ret;
    }
}


void
xqc_path_send_buffer_append(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, xqc_list_head_t *head)
{
    /* remove from conn send queue and  add to the path schduled buffer */
    xqc_list_del_init(&packet_out->po_list);
    xqc_list_add_tail(&packet_out->po_list, head);

    packet_out->po_path_id = path->path_id;

    if (!(packet_out->po_flag & XQC_POF_IN_PATH_BUF_LIST)) {
        packet_out->po_flag |= XQC_POF_IN_PATH_BUF_LIST;

        packet_out->po_cc_size = packet_out->po_used_size;
        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            path->path_schedule_bytes += packet_out->po_cc_size;
        }
    }
}

void
xqc_path_send_buffer_remove(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    xqc_list_del_init(&packet_out->po_list);

    if (packet_out->po_flag & XQC_POF_IN_PATH_BUF_LIST) {
        packet_out->po_flag &= ~XQC_POF_IN_PATH_BUF_LIST;

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            path->path_schedule_bytes -= packet_out->po_cc_size;
        }
    }
}


void
xqc_path_send_buffer_clear(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_list_head_t *head, xqc_send_type_t send_type)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t  *pos, *next;

    xqc_send_queue_t *send_queue = conn->conn_send_queue;

    xqc_list_for_each_reverse_safe(pos, next, &path->path_schedule_buf[send_type]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        xqc_path_send_buffer_remove(path, packet_out);

        if (packet_out->po_flag & XQC_POF_REINJECTED_REPLICA) {
            xqc_disassociate_packet_with_reinjection(packet_out->po_origin, packet_out);
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);

        } else if (head != NULL) {
             /* remove from path scheduled buffer & add to the head of conn send queue */
            xqc_send_queue_move_to_head(&packet_out->po_list, head);

        } else {
            /* 未指定 send_queue 则根据 packet 信息来决定放回 pto/lost/send */
            if (packet_out->po_flag & XQC_POF_TLP) {
                xqc_send_queue_move_to_head(&packet_out->po_list, &send_queue->sndq_pto_probe_packets);

            } else if (packet_out->po_flag & XQC_POF_RETRANSED) {
                xqc_send_queue_move_to_head(&packet_out->po_list, &send_queue->sndq_lost_packets);

            } else {
                xqc_send_queue_move_to_head(&packet_out->po_list, &send_queue->sndq_send_packets);
            }
        }
    }

    path->path_schedule_bytes = 0;
}


xqc_bool_t
xqc_is_same_addr(const struct sockaddr *sa1, const struct sockaddr *sa2)
{
    struct sockaddr_in   *sin1, *sin2;
    struct sockaddr_in6  *sin61, *sin62;

    if (sa1->sa_family != sa2->sa_family) {
        return XQC_FALSE;
    }

    switch (sa1->sa_family) {

        case AF_INET6:
            sin61 = (struct sockaddr_in6 *) sa1;
            sin62 = (struct sockaddr_in6 *) sa2;

            if (memcmp(&sin61->sin6_addr, &sin62->sin6_addr, 16) != 0) {
                return XQC_FALSE;
            }

            if (sin61->sin6_port != sin62->sin6_port) {
                return XQC_FALSE;
            }

            break;

        default: /* AF_INET */

            sin1 = (struct sockaddr_in *) sa1;
            sin2 = (struct sockaddr_in *) sa2;

            if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr) {
                return XQC_FALSE;
            }

            if (sin1->sin_port != sin2->sin_port) {
                return XQC_FALSE;
            }

            break;
    }

    return XQC_TRUE;
}

xqc_bool_t
xqc_is_same_addr_as_any_path(xqc_connection_t *conn, const struct sockaddr *peer_addr)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path = NULL;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        /* check if ip address is same with path created */
        if (xqc_is_same_addr(peer_addr, (struct sockaddr *)path->peer_addr)) {
            return XQC_TRUE;
        }
    }

    return XQC_FALSE;
}


xqc_int_t
xqc_conn_server_init_path_addr(xqc_connection_t *conn, uint64_t path_id,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen)
{
    xqc_int_t ret = XQC_OK;

    xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(conn, path_id);
    if (path == NULL) {
        return -XQC_EMP_PATH_NOT_FOUND;
    }

    if (path_id != XQC_INITIAL_PATH_ID && path->path_state != XQC_PATH_STATE_VALIDATING) {
        return -XQC_EMP_PATH_STATE_ERROR;
    }

    if (local_addr && local_addrlen > 0) {
        xqc_memcpy(path->local_addr, local_addr, local_addrlen);
        path->local_addrlen = local_addrlen;
    }

    if (peer_addr && peer_addrlen > 0) {
        xqc_memcpy(path->peer_addr, peer_addr, peer_addrlen);
        path->peer_addrlen = peer_addrlen;
    }

    if (path_id != XQC_INITIAL_PATH_ID) {
        xqc_list_head_t *pos, *next;
        xqc_path_ctx_t  *active_path = NULL;
        struct sockaddr *existed_addr = NULL;
        xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
            active_path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
            if (active_path->path_state != XQC_PATH_STATE_ACTIVE) {
                continue;
            }

            /* check if ip address is same with sub-connections created */
            if (xqc_is_same_addr(peer_addr, (struct sockaddr *)active_path->peer_addr)) {
                xqc_path_immediate_close(path);
                xqc_log(conn->engine->log, XQC_LOG_STATS, "|MP|path:%ui|conn:%s|cannot activate this path, due to the same IP|curIP:%s|conflictIP:%s|",
                        path_id, xqc_conn_addr_str(conn),
                        xqc_peer_addr_str((struct sockaddr*)peer_addr, conn->peer_addrlen),
                        xqc_local_addr_str((struct sockaddr*)active_path->peer_addr, active_path->peer_addrlen));
                return XQC_OK;
            }
        }

        /* notify and create the path context for user layer */
        if (conn->transport_cbs.path_created_notify) {
            ret = conn->transport_cbs.path_created_notify(conn, &conn->scid_set.user_scid,
                                                        path->path_id, xqc_conn_get_user_data(conn));
            if (ret != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_WARN, "|path_created_notify fail|path:%ui|", path->path_id);
                return ret;
            }
        }
    }
    
    xqc_log(conn->engine->log, XQC_LOG_STATS, "|path:%ui|%s|", path_id, xqc_path_addr_str(path));

    return XQC_OK;
}


xqc_int_t
xqc_conn_client_init_path_addr(xqc_connection_t *conn)
{
    xqc_path_ctx_t *path = conn->conn_initial_path;

    if (conn->peer_addrlen > 0) {
        xqc_memcpy(path->peer_addr, conn->peer_addr, conn->peer_addrlen);
        path->peer_addrlen = conn->peer_addrlen;
    }

    if (conn->local_addrlen > 0) {
        xqc_memcpy(path->local_addr, conn->local_addr, conn->local_addrlen);
        path->local_addrlen = conn->local_addrlen;
    }

    return XQC_OK;
}


xqc_msec_t
xqc_path_get_idle_timeout(xqc_path_ctx_t *path)
{
    return xqc_conn_get_idle_timeout(path->parent_conn);
}

void
xqc_path_validate(xqc_path_ctx_t *path)
{
    xqc_connection_t *conn = path->parent_conn;

    if (path->path_state == XQC_PATH_STATE_VALIDATING) {
        xqc_set_path_state(path, XQC_PATH_STATE_ACTIVE);
        path->parent_conn->validated_path_count++;

        if (path->path_flag & XQC_PATH_FLAG_SEND_STATUS) {
            path->path_flag &= ~XQC_PATH_FLAG_SEND_STATUS;

            xqc_int_t ret = xqc_write_path_status_frame_to_packet(conn, path);
            if (ret != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_path_status_frame_to_packet error|");
            }
        }

        /* PMTUD: reset probing info & launch probing immediately */
        if (conn->conn_settings.enable_pmtud) {
            conn->max_pkt_out_size = path->path_max_pkt_out_size;
            conn->probing_pkt_out_size = path->path_max_pkt_out_size;
            conn->probing_cnt = 0;
            conn->conn_flag |= XQC_CONN_FLAG_PMTUD_PROBING;
            xqc_timer_unset(&conn->conn_timer_manager, XQC_TIMER_PMTUD_PROBING);
        }
    }
}

xqc_bool_t
xqc_path_is_initial_path(xqc_path_ctx_t *path)
{
    xqc_connection_t *conn = path->parent_conn;
    return path->path_id == conn->conn_initial_path->path_id;
}


xqc_int_t
xqc_path_get_peer_addr(xqc_connection_t *conn, uint64_t path_id,
    struct sockaddr *addr, socklen_t addr_cap, socklen_t *peer_addr_len)
{
    xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(conn, path_id);
    if (path == NULL) {
        return -XQC_EMP_PATH_NOT_FOUND;
    }

    if (path->peer_addrlen > addr_cap) {
         return -XQC_ENOBUF;
    }

    *peer_addr_len = path->peer_addrlen;
    xqc_memcpy(addr, path->peer_addr, path->peer_addrlen);
    return XQC_OK;
}


xqc_int_t
xqc_path_get_local_addr(xqc_connection_t *conn, uint64_t path_id,
    struct sockaddr *addr, socklen_t addr_cap, socklen_t *local_addr_len)
{
    xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(conn, path_id);
    if (path == NULL) {
        return -XQC_EMP_PATH_NOT_FOUND;
    }

    if (path->local_addrlen > addr_cap) {
         return -XQC_ENOBUF;
    }

    *local_addr_len = path->local_addrlen;
    xqc_memcpy(addr, path->local_addr, path->local_addrlen);
    return XQC_OK;
}


void 
xqc_path_record_info(xqc_path_ctx_t *path, xqc_path_info_t *path_info)
{
    if (path_info == NULL) {
        return;
    }

    xqc_memset(path_info, 0, sizeof(xqc_path_info_t));

    if (path == NULL) {
        return;
    }

    path_info->path_id = path->path_id;
    path_info->path_state = (uint8_t)path->path_state;
    path_info->app_path_status = (uint8_t)path->app_path_status;
    path_info->tra_path_status = (uint8_t)path->tra_path_status;
    path_info->path_bytes_send = path->path_send_ctl->ctl_bytes_send;
    path_info->path_bytes_recv = path->path_send_ctl->ctl_bytes_recv;

    path_info->path_create_time = (path->path_create_time - path->parent_conn->conn_create_time)/1000;
    if (path->path_destroy_time > 0) {
        path_info->path_destroy_time = (path->path_destroy_time - path->parent_conn->conn_create_time)/1000;
    }

    path_info->standby_probe_count = path->standby_probe_count;
    path_info->app_path_status_changed_count = path->app_path_status_changed_count;
    path_info->tra_path_status_changed_count = path->tra_path_status_changed_count;

    path_info->pkt_recv_cnt = path->path_send_ctl->ctl_recv_count;
    path_info->pkt_send_cnt = path->path_send_ctl->ctl_send_count;
    path_info->dgram_recv_cnt = path->path_send_ctl->ctl_dgram_recv_count;
    path_info->dgram_send_cnt = path->path_send_ctl->ctl_dgram_send_count;
    path_info->red_dgram_recv_cnt = path->path_send_ctl->ctl_reinj_dgram_recv_count;
    path_info->red_dgram_send_cnt = path->path_send_ctl->ctl_reinj_dgram_send_count;
    path_info->srtt = path->path_send_ctl->ctl_srtt;
    path_info->loss_cnt = path->path_send_ctl->ctl_lost_count;
    path_info->tlp_cnt = path->path_send_ctl->ctl_tlp_count;
}

xqc_bool_t 
xqc_path_is_full(xqc_path_ctx_t *path)
{
    xqc_send_ctl_t *ctl = path->path_send_ctl;
    uint64_t bytes_on_path = path->path_schedule_bytes + ctl->ctl_bytes_in_flight;
    uint64_t cwnd = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
    return (bytes_on_path + xqc_conn_get_mss(path->parent_conn)) > cwnd;
}
void
xqc_set_application_path_status(xqc_path_ctx_t *path, xqc_app_path_status_t status, xqc_usec_t now)
{
    if (path->app_path_status == status) {
        return;
    }

    xqc_log(path->parent_conn->log, XQC_LOG_DEBUG, "|path:%ui|app_path_status:%d->%d|", path->path_id, path->app_path_status, status);
    path->app_path_status = status;

    path->app_path_status_changed_count++;
    path->last_app_path_status_changed_time = now;
    xqc_set_transport_path_status(path, (xqc_tra_path_status_t)status, now);
}

void xqc_set_transport_path_status(xqc_path_ctx_t *path, xqc_tra_path_status_t status, xqc_usec_t now)
{
    if (path->tra_path_status == status) {
        return;
    }

    xqc_connection_t *conn = path->parent_conn;

    if (path->path_state == XQC_PATH_STATE_ACTIVE) {

        if ((path->tra_path_status == XQC_TRA_PATH_STATUS_IN_USE)
            && (status != XQC_TRA_PATH_STATUS_IN_USE))
        {
            conn->in_use_active_path_count--;

        } else if ((path->tra_path_status != XQC_TRA_PATH_STATUS_IN_USE)
                   && (status == XQC_TRA_PATH_STATUS_IN_USE))
        {
            conn->in_use_active_path_count++;
        }

    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|tra_path_status:%d->%d|", path->path_id, path->tra_path_status, status);
    path->tra_path_status = status;

    path->tra_path_status_changed_count++;
    path->last_tra_path_status_changed_time = now;

    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    send_ctl->ctl_pto_count_since_last_tra_path_status_changed = 0;
    send_ctl->ctl_send_count_at_last_tra_path_status_changed_time = send_ctl->ctl_send_count;
}


xqc_int_t
xqc_conn_mark_path_standby(xqc_engine_t *engine, const xqc_cid_t *cid, uint64_t path_id)
{
    xqc_connection_t *conn = NULL;
    xqc_path_ctx_t *path = NULL;

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return -XQC_ECONN_NFOUND;
    }
    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return -XQC_CLOSING;
    }

    /* check mp-support */
    if (!conn->enable_multipath) {
        xqc_log(engine->log, XQC_LOG_WARN,
                "|Multipath is not supported in connection|%p|", conn);
        return -XQC_EMP_NOT_SUPPORT_MP;
    }

    /* find path */
    path = xqc_conn_find_path_by_path_id(conn, path_id);
    if (path == NULL) {
        xqc_log(engine->log, XQC_LOG_WARN,
                "|path is not found by path_id in connection|%p|%ui|", 
                conn, path_id);
        return -XQC_EMP_PATH_NOT_FOUND;
    }

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_set_application_path_status(path, XQC_APP_PATH_STATUS_STANDBY, now);

    if (path->path_state < XQC_PATH_STATE_ACTIVE) {
        path->path_flag |= XQC_PATH_FLAG_SEND_STATUS;
        return XQC_OK;
    }

    xqc_int_t ret = xqc_write_path_status_frame_to_packet(conn, path);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_path_status_frame_to_packet error|%d|", ret);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_mark_path_available(xqc_engine_t *engine, const xqc_cid_t *cid, uint64_t path_id)
{
    xqc_connection_t *conn = NULL;
    xqc_path_ctx_t *path = NULL;

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return -XQC_ECONN_NFOUND;
    }
    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return -XQC_CLOSING;
    }

    /* check mp-support */
    if (!conn->enable_multipath) {
        xqc_log(engine->log, XQC_LOG_WARN,
                "|Multipath is not supported in connection|%p|", conn);
        return -XQC_EMP_NOT_SUPPORT_MP;
    }

    /* find path */
    path = xqc_conn_find_path_by_path_id(conn, path_id);
    if (path == NULL) {
        xqc_log(engine->log, XQC_LOG_WARN,
                "|path is not found by path_id in connection|%p|%ui|", 
                conn, path_id);
        return -XQC_EMP_PATH_NOT_FOUND;
    }

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_set_application_path_status(path, XQC_APP_PATH_STATUS_AVAILABLE, now);

    if (path->path_state < XQC_PATH_STATE_ACTIVE) {
        path->path_flag |= XQC_PATH_FLAG_SEND_STATUS;
        return XQC_OK;
    }

    xqc_int_t ret = xqc_write_path_status_frame_to_packet(conn, path);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_path_status_frame_to_packet error|%d|", ret);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_path_standby_probe(xqc_path_ctx_t *path)
{
    xqc_connection_t *conn = path->parent_conn;

    xqc_int_t ret = xqc_path_send_ping_to_probe(path, XQC_PNS_APP_DATA);
    if (ret != XQC_OK) {
        return ret;
    }

    path->standby_probe_count++;
    return XQC_OK;
}

xqc_path_stats_t
xqc_path_get_stats(xqc_engine_t *engine, const xqc_cid_t *cid, uint64_t path_id)
{
    xqc_connection_t *conn;
    xqc_path_ctx_t *path;
    xqc_path_stats_t path_stats;
    xqc_memzero(&path_stats, sizeof(path_stats));
    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return path_stats;
    }
    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return path_stats;
    }
    path = xqc_conn_find_path_by_path_id(conn, path_id);
    if (path == NULL) {
        xqc_log(engine->log, XQC_LOG_WARN, "|path is not found by path_id in connection|");
        return path_stats;
    }
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    path_stats.last_tra_path_status_changed_time = path->last_tra_path_status_changed_time;
    path_stats.send_count_since_last_tra_path_status_changed =
        send_ctl->ctl_send_count - send_ctl->ctl_send_count_at_last_tra_path_status_changed_time;
    path_stats.pto_count_since_last_tra_path_status_changed = send_ctl->ctl_pto_count_since_last_tra_path_status_changed;
    path_stats.get_stats_success = 1;
    return path_stats;
}
