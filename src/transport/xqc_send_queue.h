#ifndef _XQC_SEND_QUEUE_H_INCLUDED_
#define _XQC_SEND_QUEUE_H_INCLUDED_

#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"


#define XQC_SNDQ_PACKETS_USED_MAX            18000
#define XQC_SNDQ_RELEASE_ENOUGH_SPACE_TH     10  /* 1 / 10*/

typedef struct xqc_send_queue_s {

    xqc_connection_t           *sndq_conn;

    /* send queue for packets, should be in connection level */
    xqc_list_head_t             sndq_send_packets;                  /* xqc_packet_out_t to send */
    xqc_list_head_t             sndq_send_packets_high_pri;         /* xqc_packet_out_t to send with high priority */
    xqc_list_head_t             sndq_unacked_packets[XQC_PNS_N];    /* xqc_packet_out_t */

    xqc_list_head_t             sndq_lost_packets;                  /* xqc_packet_out_t */
    xqc_list_head_t             sndq_free_packets;                  /* xqc_packet_out_t */
    xqc_list_head_t             sndq_buff_1rtt_packets;             /* xqc_packet_out_t buff 1RTT before handshake complete */
    xqc_list_head_t             sndq_pto_probe_packets;             /* xqc_packet_out_t */

    uint64_t                    sndq_packets_in_unacked_list;       /* to estimate bytes in the lists except for unacked list */
    uint64_t                    sndq_packets_used;
    uint64_t                    sndq_packets_used_bytes;
    uint64_t                    sndq_packets_free;
    uint64_t                    sndq_packets_used_max;

    xqc_bool_t                  sndq_full;

} xqc_send_queue_t;


static inline int
xqc_send_queue_can_write(xqc_send_queue_t *send_queue)
{
    if (send_queue->sndq_packets_used < send_queue->sndq_packets_used_max) {
        return XQC_TRUE;
    }
    return XQC_FALSE;
}

static inline xqc_bool_t
xqc_send_queue_release_enough_space(xqc_send_queue_t *send_queue)
{
    return (send_queue->sndq_packets_used_max - send_queue->sndq_packets_used)
            >= (send_queue->sndq_packets_used_max / XQC_SNDQ_RELEASE_ENOUGH_SPACE_TH);
}
uint64_t xqc_send_queue_get_unsent_packets_num(xqc_send_queue_t *send_queue);


xqc_send_queue_t *xqc_send_queue_create(xqc_connection_t *conn);
void xqc_send_queue_destroy(xqc_send_queue_t *send_queue);

void xqc_send_queue_destroy_packets_list(xqc_list_head_t *head);
void xqc_send_queue_pre_destroy_packets_list(xqc_send_queue_t *send_queue, xqc_list_head_t *head);

xqc_packet_out_t *xqc_send_queue_get_packet_out(xqc_send_queue_t *send_queue, unsigned need, xqc_pkt_type_t pkt_type);
xqc_packet_out_t *xqc_send_queue_get_packet_out_for_stream(xqc_send_queue_t *send_queue, unsigned need, xqc_pkt_type_t pkt_type,
    xqc_stream_t *stream);
int xqc_send_queue_out_queue_empty(xqc_send_queue_t *send_queue);


void xqc_send_queue_insert_send(xqc_packet_out_t *po, xqc_list_head_t *head, xqc_send_queue_t *send_queue);
void xqc_send_queue_remove_send(xqc_list_head_t *pos);

void xqc_send_queue_insert_lost(xqc_list_head_t *pos, xqc_list_head_t *head);
void xqc_send_queue_remove_lost(xqc_list_head_t *pos);

void xqc_send_queue_insert_free(xqc_packet_out_t *po, xqc_list_head_t *head, xqc_send_queue_t *send_queue);
void xqc_send_queue_remove_free(xqc_list_head_t *pos, xqc_send_queue_t *send_queue);

void xqc_send_queue_insert_buff(xqc_list_head_t *pos, xqc_list_head_t *head);
void xqc_send_queue_remove_buff(xqc_list_head_t *pos, xqc_send_queue_t *send_queue);

void xqc_send_queue_insert_probe(xqc_list_head_t *pos, xqc_list_head_t *head);
void xqc_send_queue_remove_probe(xqc_list_head_t *pos);

void xqc_send_queue_insert_unacked(xqc_packet_out_t *packet_out, xqc_list_head_t *head, xqc_send_queue_t *send_queue);
void xqc_send_queue_remove_unacked(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue);


void xqc_send_queue_move_to_head(xqc_list_head_t *pos, xqc_list_head_t *head);
void xqc_send_queue_move_to_tail(xqc_list_head_t *pos, xqc_list_head_t *head);
void xqc_send_queue_move_to_high_pri(xqc_list_head_t *pos, xqc_send_queue_t *send_queue);

void xqc_send_queue_copy_to_lost(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue, xqc_bool_t mark_retrans);
void xqc_send_queue_copy_to_probe(xqc_packet_out_t *packet_out, xqc_send_queue_t *send_queue, xqc_path_ctx_t *path);


void xqc_send_queue_drop_packets(xqc_connection_t *conn);
void xqc_send_queue_drop_0rtt_packets(xqc_connection_t *conn);
void xqc_send_queue_drop_initial_packets(xqc_connection_t *conn);
void xqc_send_queue_drop_handshake_packets(xqc_connection_t *conn);
void xqc_send_queue_drop_stream_frame_packets(xqc_connection_t *conn, xqc_stream_id_t stream_id);




#endif /* _XQC_SEND_QUEUE_H_INCLUDED_ */




