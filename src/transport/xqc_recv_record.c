/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/common/xqc_log.h"

void
xqc_recv_record_log(xqc_connection_t *conn, xqc_recv_record_t *recv_record)
{
    if (conn->log->log_level < XQC_LOG_DEBUG) {
        return;
    }
    xqc_list_head_t *pos, *next;
    xqc_pktno_range_node_t *pnode;
    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|low:%ui|high:%ui|",
                pnode->pktno_range.low, pnode->pktno_range.high);
    }
}

void
xqc_recv_record_print(xqc_connection_t *conn, xqc_recv_record_t *recv_record, char *buff, unsigned buff_size)
{
    xqc_list_head_t *pos, *next;
    xqc_pktno_range_node_t *pnode;
    buff[0] = '\0';
    xqc_pktno_range_t range[3]; /* record up to 3 segments */
    memset(&range, 0, sizeof(range));
    int range_count = 0;

    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        range[range_count].high = pnode->pktno_range.high;
        range[range_count].low = pnode->pktno_range.low;
        range_count++;
        if (range_count >= 3) {
            break;
        }
    }

    snprintf(buff, buff_size, "#%"PRIu64"-%"PRIu64"#%"PRIu64"-%"PRIu64"#%"PRIu64"-%"PRIu64"#v0429",
             range[0].high, range[0].low,
             range[1].high, range[1].low,
             range[2].high, range[2].low);
}

static int
xqc_pktno_range_can_merge(xqc_pktno_range_node_t *node, xqc_packet_number_t packet_number)
{
    if (node->pktno_range.low - 1 == packet_number) {
        --node->pktno_range.low;
        return 1;
    }

    if (node->pktno_range.high + 1 == packet_number) {
        ++node->pktno_range.high;
        return 1;
    }

    return 0;
}

/**
 * insert into range list when receive a new packet
 */
xqc_pkt_range_status
xqc_recv_record_add(xqc_recv_record_t *recv_record, xqc_packet_number_t packet_number)
{
    xqc_list_head_t *pos, *prev, *next;
    xqc_pktno_range_node_t *pnode, *prev_node;
    xqc_pktno_range_t range;
    pnode = prev_node = NULL;
    pos = prev = NULL;
    int pos_find = 0;

    xqc_pktno_range_node_t *first = NULL;
    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        first = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        break;
    }

    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        if (packet_number <= pnode->pktno_range.high) {
            if (packet_number >= pnode->pktno_range.low) {
                return XQC_PKTRANGE_DUP;
            }

        } else {
            pos_find = 1;
            break;
        }
        prev = pos;
    }

    if (pos_find) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
    }

    if (prev) {
        prev_node = xqc_list_entry(prev, xqc_pktno_range_node_t, list);
    }

    if ((prev_node && xqc_pktno_range_can_merge(prev_node, packet_number))
        || (pnode && xqc_pktno_range_can_merge(pnode, packet_number)))
    {
        if (prev_node && pnode && (prev_node->pktno_range.low - 1 == pnode->pktno_range.high)) {
            prev_node->pktno_range.low = pnode->pktno_range.low;
            xqc_list_del_init(pos);
            recv_record->node_count--;
            xqc_free(pnode);
        }

    } else {
        xqc_pktno_range_node_t *new_node = xqc_calloc(1, sizeof(*new_node));
        if (!new_node) {
            return XQC_PKTRANGE_ERR;
        }
        new_node->pktno_range.low = new_node->pktno_range.high = packet_number;
        if (pos_find) {
            /* insert before pos */
            xqc_list_add_tail(&(new_node->list), pos);
            recv_record->node_count++;

            /* delete last node if exceed MAX RANGE */
            if (recv_record->node_count > XQC_MAX_ACK_RANGE_CNT) {
                xqc_list_for_each_reverse_safe(pos, next, &recv_record->list_head) {
                    pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
                    xqc_list_del_init(pos);
                    recv_record->node_count--;
                    xqc_free(pnode);
                    if (recv_record->node_count <= XQC_MAX_ACK_RANGE_CNT) {
                        break;
                    }
                }
            }
        } else {
            /* insert tail of the list */
            if (recv_record->node_count < XQC_MAX_ACK_RANGE_CNT) {
                xqc_list_add_tail(&(new_node->list), &recv_record->list_head);
                recv_record->node_count++;
            } else {
                xqc_free(new_node);
            }
        }
    }

    return XQC_PKTRANGE_OK;
}

/**
 * del packet number range < del_from
 */
void
xqc_recv_record_del(xqc_recv_record_t *recv_record, xqc_packet_number_t del_from)
{
    if (del_from < recv_record->rr_del_from) {
        return;
    }

    xqc_list_head_t *pos, *next;
    xqc_pktno_range_node_t *pnode;
    xqc_pktno_range_t *range;

    recv_record->rr_del_from = del_from;

    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        range = &pnode->pktno_range;

        if (range->low < del_from) {
            if (range->high < del_from) {
                xqc_list_del_init(pos);
                recv_record->node_count--;
                xqc_free(pnode);

            } else {
                range->low = del_from;
            }
        }
    }
}

void
xqc_recv_record_destroy(xqc_recv_record_t *recv_record)
{
    xqc_list_head_t *pos, *next;
    xqc_pktno_range_node_t *pnode;
    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        xqc_list_del_init(pos);
        xqc_free(pnode);
    }
    recv_record->node_count = 0;
    recv_record->rr_del_from = 0;
}

/* 把src的链表逐个节点移动到dst */
void 
xqc_recv_record_move(xqc_recv_record_t *dst, xqc_recv_record_t *src)
{
    if (!dst || !src)
        return;
    
    xqc_recv_record_destroy(dst);

    if (!xqc_list_empty(&src->list_head)) {
        src->list_head.next->prev = &dst->list_head;
        dst->list_head.next = src->list_head.next;
        src->list_head.prev->next = &dst->list_head;
        dst->list_head.prev = src->list_head.prev;
        xqc_init_list_head(&src->list_head);
    }

    dst->rr_del_from = src->rr_del_from;
    src->rr_del_from = 0;
    dst->node_count = src->node_count;
    src->node_count = 0;
}

xqc_packet_number_t
xqc_recv_record_largest(xqc_recv_record_t *recv_record)
{
    xqc_pktno_range_node_t *pnode = NULL;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &recv_record->list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        break;
    }

    if (pnode) {
        return pnode->pktno_range.high;

    } else {
        return 0;
    }
}

uint32_t
xqc_get_ack_frequency(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    if(xqc_conn_is_handshake_confirmed(conn)
       && conn->conn_settings.adaptive_ack_frequency
       && path->path_send_ctl->ctl_ack_sent_cnt >= 100)
    {
        // slow down ack rate if we have sent more than 100 ACKs
        return xqc_max(conn->conn_settings.ack_frequency, 10);
    }

    return conn->conn_settings.ack_frequency; 
}

void
xqc_maybe_should_ack(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_pn_ctl_t *pn_ctl, xqc_pkt_num_space_t pns, int out_of_order, xqc_usec_t now)
{
    /*
     * Generating Acknowledgements
     */

    if (path->path_flag & (XQC_PATH_FLAG_SHOULD_ACK_INIT << pns)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|already yes|");
        return;
    }

    if (pns == XQC_PNS_HSK
        && (xqc_tls_is_key_ready(conn->tls, XQC_ENC_LEV_HSK, XQC_KEY_TYPE_TX_WRITE) == XQC_FALSE))
    {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|delay|handshake ack should send after tx key ready|");
        return;

    } else if (pns == XQC_PNS_APP_DATA && !(conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|delay|01RTT ack should send after handshake complete|");
        return;
    }

    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint32_t ack_frequency = xqc_get_ack_frequency(conn, path);

    if (send_ctl->ctl_ack_eliciting_pkt[pns] >= ack_frequency
        || (pns <= XQC_PNS_HSK && send_ctl->ctl_ack_eliciting_pkt[pns] >= 1)
        || (out_of_order && send_ctl->ctl_ack_eliciting_pkt[pns] >= 1))
    {
        path->path_flag |= XQC_PATH_FLAG_SHOULD_ACK_INIT << pns;
        conn->ack_flag |= (1 << (pns + path->path_id * XQC_PNS_N));
        
        xqc_timer_unset(&send_ctl->path_timer_manager, XQC_TIMER_ACK_INIT + pns);

        xqc_log(conn->log, XQC_LOG_DEBUG, "|yes|path:%ui|out_of_order:%d|ack_eliciting_pkt:%ud|"
                "pns:%d|flag:%s|ack_freq:%ud|", 
                path->path_id, out_of_order, 
                send_ctl->ctl_ack_eliciting_pkt[pns],
                pns, xqc_conn_flag_2_str(conn, conn->conn_flag),
                ack_frequency);

    } else if (send_ctl->ctl_ack_eliciting_pkt[pns] > 0
               && !xqc_timer_is_set(&send_ctl->path_timer_manager, XQC_TIMER_ACK_INIT + pns))
    {
        xqc_timer_set(&send_ctl->path_timer_manager, XQC_TIMER_ACK_INIT + pns,
                      now, conn->local_settings.max_ack_delay * 1000);

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|path:%ui|set ack timer|ack_eliciting_pkt:%ud|pns:%d|flag:%s|now:%ui|max_ack_delay:%ui|",
                path->path_id,
                send_ctl->ctl_ack_eliciting_pkt[pns], pns, xqc_conn_flag_2_str(conn, conn->conn_flag),
                now, conn->local_settings.max_ack_delay * 1000);
    }
}

int
xqc_ack_sent_record_init(xqc_ack_sent_record_t *record)
{
    record->last_add_time = 0;
    record->ack_sent = xqc_rarray_create(8, sizeof(xqc_ack_sent_entry_t));
    if (!record->ack_sent) {
        return XQC_ERROR;
    }
    return XQC_OK;
}

void 
xqc_ack_sent_record_reset(xqc_ack_sent_record_t *record)
{
    record->last_add_time = 0;
    xqc_rarray_reinit(record->ack_sent);
}

void
xqc_ack_sent_record_destroy(xqc_ack_sent_record_t *record)
{
    if (record->ack_sent) {
        xqc_rarray_destroy(record->ack_sent);
        record->ack_sent = NULL;
    }
}

int
xqc_ack_sent_record_add(xqc_ack_sent_record_t *record, xqc_packet_out_t *packet_out, xqc_usec_t srtt, xqc_usec_t now)
{
    /* Record once per round trip */
    if (record->last_add_time + srtt > now) {
        return XQC_OK;
    }

    xqc_rarray_t *ra = record->ack_sent;

    if (xqc_rarray_full(ra)) {
        xqc_rarray_pop_back(ra);
    }

    xqc_ack_sent_entry_t *entry = xqc_rarray_push_front(ra);
    if (!entry) {
        return XQC_ERROR;
    }
    entry->pkt_num = packet_out->po_pkt.pkt_num;
    entry->largest_ack = packet_out->po_largest_ack;

    record->last_add_time = now;

    return XQC_OK;
}

xqc_packet_number_t
xqc_ack_sent_record_on_ack(xqc_ack_sent_record_t *record, xqc_ack_info_t *ack_info)
{
    xqc_pktno_range_t *range = &ack_info->ranges[0];
    xqc_rarray_t *ra = record->ack_sent;
    uint64_t size = xqc_rarray_size(ra);
    xqc_ack_sent_entry_t *entry;

    for (uint64_t i = 0; i < size; i++) {
        entry = xqc_rarray_get(ra, i);
        if (!entry) {
            return 0;
        }

        while (entry->pkt_num < range->low) {
            if (range == &ack_info->ranges[ack_info->n_ranges - 1]) {
                return 0;
            }
            ++range;
        }
        if (entry->pkt_num <= range->high && entry->pkt_num >= range->low) {
            xqc_rarray_pop_from(ra, i);
            return entry->largest_ack;
        }
    }
    return 0;
}