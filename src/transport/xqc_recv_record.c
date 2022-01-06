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
xqc_recv_record_add(xqc_recv_record_t *recv_record, xqc_packet_number_t packet_number, xqc_usec_t recv_time)
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

    if (first && packet_number > first->pktno_range.high) {
        recv_record->largest_pkt_recv_time = recv_time;

    } else if (!first) {
        recv_record->largest_pkt_recv_time = recv_time;
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

        } else {
            /* insert tail of the list */
            xqc_list_add_tail(&(new_node->list), &recv_record->list_head);
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

void
xqc_maybe_should_ack(xqc_connection_t *conn, xqc_pkt_num_space_t pns, int out_of_order, xqc_usec_t now)
{
    /*
     * Generating Acknowledgements
     */

    if (conn->conn_flag & (XQC_CONN_FLAG_SHOULD_ACK_INIT << pns)) {
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

    if (conn->ack_eliciting_pkt[pns] >= 2
        || (pns <= XQC_PNS_HSK && conn->ack_eliciting_pkt[pns] >= 1)
        || (out_of_order && conn->ack_eliciting_pkt[pns] >= 1))
    {
        conn->conn_flag |= XQC_CONN_FLAG_SHOULD_ACK_INIT << pns;
        xqc_send_ctl_timer_unset(conn->conn_send_ctl, XQC_TIMER_ACK_INIT + pns);

        xqc_log(conn->log, XQC_LOG_DEBUG, "|yes|out_of_order:%d|ack_eliciting_pkt:%ud|"
                "pns:%d|flag:%s|", out_of_order, conn->ack_eliciting_pkt[pns],
                pns, xqc_conn_flag_2_str(conn->conn_flag));

    } else if (conn->ack_eliciting_pkt[pns] > 0
               && !xqc_send_ctl_timer_is_set(conn->conn_send_ctl, XQC_TIMER_ACK_INIT + pns))
    {
        xqc_send_ctl_timer_set(conn->conn_send_ctl, XQC_TIMER_ACK_INIT + pns,
                               now, conn->local_settings.max_ack_delay*1000);

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|set ack timer|ack_eliciting_pkt:%ud|pns:%d|flag:%s|now:%ui|max_ack_delay:%ui|",
                conn->ack_eliciting_pkt[pns], pns, xqc_conn_flag_2_str(conn->conn_flag),
                now, conn->local_settings.max_ack_delay*1000);
    }
}
