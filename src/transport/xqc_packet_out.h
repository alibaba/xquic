/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_PACKET_OUT_H_INCLUDED_
#define _XQC_PACKET_OUT_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_frame.h"
#include "src/tls/xqc_tls_defs.h"

/*
 * https://datatracker.ietf.org/doc/html/rfc9000#section-14.2
 * In the absence of these mechanisms, QUIC endpoints SHOULD NOT send
 * datagrams larger than the smallest allowed maximum datagram size.
 */
#define XQC_PACKET_OUT_SIZE         XQC_QUIC_MSS  /* without XQC_EXTRA_SPACE & XQC_ACK_SPACE */
#define XQC_EXTRA_SPACE             XQC_TLS_AEAD_OVERHEAD_MAX_LEN
#define XQC_ACK_SPACE               16
#define XQC_PACKET_OUT_SIZE_EXT     (XQC_PACKET_OUT_SIZE + XQC_EXTRA_SPACE + XQC_ACK_SPACE)

#define XQC_MAX_STREAM_FRAME_IN_PO  3

typedef enum {
    XQC_POF_IN_FLIGHT        = 1 << 0,
    XQC_POF_LOST             = 1 << 1,
    XQC_POF_DCID_NOT_DONE    = 1 << 2,
    XQC_POF_RESERVED         = 1 << 3,
    XQC_POF_TLP              = 1 << 4,
    XQC_POF_STREAM_UNACK     = 1 << 5,
    XQC_POF_RETRANSED        = 1 << 6,
    XQC_POF_NOTIFY           = 1 << 7,  /* need to notify user when a packet is acked, lost, etc. */
} xqc_packet_out_flag_t;

typedef struct xqc_po_stream_frame_s {
    xqc_stream_id_t         ps_stream_id;
    unsigned char           ps_is_used;
    unsigned char           ps_has_fin;     /* whether fin flag from stream frame is set  */
    unsigned char           ps_is_reset;    /* whether frame is RESET_STREAM */
} xqc_po_stream_frame_t;

typedef struct xqc_packet_out_s {
    xqc_packet_t            po_pkt;
    xqc_list_head_t         po_list;

    /* pointers should carefully assign in xqc_packet_out_copy */
    unsigned char          *po_buf;
    unsigned char          *po_ppktno;
    unsigned char          *po_payload;
    xqc_packet_out_t       *po_origin;          /* point to original packet before retransmitted */
    void                   *po_user_data;       /* used to differ inner PING and user PING */

    unsigned int            po_buf_size;
    unsigned int            po_used_size;
    unsigned int            po_ack_offset;
    xqc_packet_out_flag_t   po_flag;
    /* Largest Acknowledged in ACK frame, initiated to be 0 */
    xqc_packet_number_t     po_largest_ack;
    xqc_usec_t              po_sent_time;
    xqc_frame_type_bit_t    po_frame_types;

    /* the stream related to stream frame */
    xqc_po_stream_frame_t   po_stream_frames[XQC_MAX_STREAM_FRAME_IN_PO];
    uint32_t                po_origin_ref_cnt;  /* reference count of original packet */
    uint32_t                po_acked;
    uint64_t                po_delivered;       /* the sum of delivered data before sending packet P */
    xqc_usec_t              po_delivered_time;  /* the time of last acked packet before sending packet P */
    xqc_usec_t              po_first_sent_time; /* the time of first sent packet during current sample period */
    xqc_bool_t              po_is_app_limited;

    /* For BBRv2 */
    /* the inflight bytes when the packet is sent (including itself) */
    uint64_t                po_tx_in_flight; 
    /* how many packets have been lost when the packet is sent */
    uint32_t                po_lost; 

    uint64_t                po_path_id;
} xqc_packet_out_t;

xqc_packet_out_t *xqc_packet_out_create();

void xqc_packet_out_copy(xqc_packet_out_t *dst, xqc_packet_out_t *src);

xqc_packet_out_t *xqc_packet_out_get(xqc_send_ctl_t *ctl);

xqc_packet_out_t *xqc_packet_out_get_and_insert_send(xqc_send_ctl_t *ctl, enum xqc_pkt_type pkt_type);

void xqc_packet_out_destroy(xqc_packet_out_t *packet_out);

void xqc_maybe_recycle_packet_out(xqc_packet_out_t *packet_out, xqc_connection_t *conn);

xqc_packet_out_t *xqc_write_new_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type);

xqc_packet_out_t *xqc_write_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need);

int xqc_write_packet_header(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

int xqc_write_ack_to_packets(xqc_connection_t *conn);

int xqc_write_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns);

int xqc_write_ping_to_packet(xqc_connection_t *conn, void *po_user_data, xqc_bool_t notify);

int xqc_write_conn_close_to_packet(xqc_connection_t *conn, uint64_t err_code);

int xqc_write_reset_stream_to_packet(xqc_connection_t *conn, xqc_stream_t *stream, uint64_t err_code, uint64_t final_size);

int xqc_write_stop_sending_to_packet(xqc_connection_t *conn, xqc_stream_t *stream, uint64_t err_code);

int xqc_write_data_blocked_to_packet(xqc_connection_t *conn, uint64_t data_limit);

int xqc_write_stream_data_blocked_to_packet(xqc_connection_t *conn, xqc_stream_id_t stream_id, uint64_t stream_data_limit);

int xqc_write_streams_blocked_to_packet(xqc_connection_t *conn, uint64_t stream_limit, int bidirectional);

int xqc_write_max_data_to_packet(xqc_connection_t *conn, uint64_t max_data);

int xqc_write_max_stream_data_to_packet(xqc_connection_t *conn, xqc_stream_id_t stream_id, uint64_t max_stream_data);

int xqc_write_max_streams_to_packet(xqc_connection_t *conn, uint64_t max_stream, int bidirectional);

int xqc_write_new_token_to_packet(xqc_connection_t *conn);

int xqc_write_stream_frame_to_packet(xqc_connection_t *conn, xqc_stream_t *stream, xqc_pkt_type_t pkt_type,
    uint8_t fin, const unsigned char *payload, size_t payload_size, size_t *send_data_written);

int xqc_write_handshake_done_frame_to_packet(xqc_connection_t *conn);

xqc_int_t xqc_write_new_conn_id_frame_to_packet(xqc_connection_t *conn, uint64_t retire_prior_to);

xqc_int_t xqc_write_retire_conn_id_frame_to_packet(xqc_connection_t *conn, uint64_t seq_num);

xqc_int_t xqc_write_path_status_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path);


#endif /* _XQC_PACKET_OUT_H_INCLUDED_ */
