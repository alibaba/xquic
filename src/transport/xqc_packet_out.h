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
/* without XQC_EXTRA_SPACE & XQC_ACK_SPACE */
#define XQC_MAX_PACKET_OUT_SIZE  XQC_QUIC_MAX_MSS
#define XQC_PACKET_OUT_SIZE      XQC_QUIC_MIN_MSS  
#define XQC_PACKET_OUT_EXT_SPACE (XQC_TLS_AEAD_OVERHEAD_MAX_LEN + XQC_ACK_SPACE)
#define XQC_PACKET_OUT_BUF_CAP   (XQC_MAX_PACKET_OUT_SIZE + XQC_PACKET_OUT_EXT_SPACE)

#define XQC_MAX_STREAM_FRAME_IN_PO  3

typedef enum {
    XQC_POF_IN_FLIGHT           = 1 << 0,
    XQC_POF_LOST                = 1 << 1,
    XQC_POF_DCID_NOT_DONE       = 1 << 2,
    XQC_POF_RESERVED            = 1 << 3,
    XQC_POF_TLP                 = 1 << 4,
    XQC_POF_STREAM_UNACK        = 1 << 5,
    XQC_POF_RETRANSED           = 1 << 6,
    XQC_POF_NOTIFY              = 1 << 7,  /* need to notify user when a packet is acked, lost, etc. */
    XQC_POF_RESEND              = 1 << 8,
    XQC_POF_REINJECTED_ORIGIN   = 1 << 9,
    XQC_POF_REINJECTED_REPLICA  = 1 << 10,
    XQC_POF_IN_PATH_BUF_LIST    = 1 << 11, /* FIXED: reset when copy */
    XQC_POF_IN_UNACK_LIST       = 1 << 12, /* FIXED: reset when copy */
    XQC_POF_NOT_SCHEDULE        = 1 << 13,
    XQC_POF_NOT_REINJECT        = 1 << 14,
    XQC_POF_DROPPED_DGRAM       = 1 << 15,
    XQC_POF_REINJECT_DIFF_PATH  = 1 << 16,
    XQC_POF_PMTUD_PROBING       = 1 << 17,
    XQC_POF_QOS_HIGH            = 1 << 18,
    XQC_POF_QOS_PROBING         = 1 << 19,
    XQC_POF_SPURIOUS_LOSS       = 1 << 20,
} xqc_packet_out_flag_t;

typedef struct xqc_po_stream_frame_s {
    xqc_stream_id_t         ps_stream_id;
    uint64_t                ps_offset;
    unsigned int            ps_length;
    unsigned int            ps_type_offset;
    unsigned int            ps_length_offset;
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
    unsigned char          *po_padding;         /* used to reassemble packets carrying new header */

    size_t                  po_buf_cap;         /* capcacity of po_buf */
    unsigned int            po_buf_size;        /* size of po_buf can be used */
    unsigned int            po_used_size;
    unsigned int            po_enc_size;        /* size of po after being encrypted */
    unsigned int            po_ack_offset;
    xqc_packet_out_flag_t   po_flag;
    /* Largest Acknowledged in ACK frame, initiated to be 0 */
    xqc_packet_number_t     po_largest_ack;
    xqc_usec_t              po_sent_time;
    xqc_frame_type_bit_t    po_frame_types;

    /* the stream related to stream frame */
    xqc_po_stream_frame_t   po_stream_frames[XQC_MAX_STREAM_FRAME_IN_PO];
    unsigned int            po_stream_frames_idx;

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

    /* only meaningful if it contains a DATAGRAM frame */
    uint64_t                po_dgram_id;

    /* Multipath */
    uint8_t                 po_path_flag;
    uint64_t                po_path_id;
    unsigned int            po_cc_size; /* TODO: check cc size != send size */

    /* Reinjection */
    uint64_t                po_stream_offset;
    uint64_t                po_stream_id;

    /* PMTUD Probing */
    size_t                  po_max_pkt_out_size;

    size_t                  po_reserved_size;

    /* ping notification */
    xqc_ping_record_t      *po_pr;

    xqc_usec_t              po_sched_cwnd_blk_ts;
    xqc_usec_t              po_send_cwnd_blk_ts;
    xqc_usec_t              po_send_pacing_blk_ts;
} xqc_packet_out_t;

xqc_bool_t xqc_packet_out_on_specific_path(xqc_connection_t *conn, 
    xqc_packet_out_t *po, xqc_path_ctx_t **path);

xqc_bool_t xqc_packet_out_can_attach_ack(xqc_packet_out_t *po, 
    xqc_path_ctx_t *path, xqc_pkt_type_t pkt_type);

xqc_bool_t xqc_packet_out_can_pto_probe(xqc_packet_out_t *po, uint64_t path_id);

void xqc_packet_out_remove_ack_frame(xqc_packet_out_t *po);

xqc_packet_out_t *xqc_packet_out_create(size_t po_buf_cap);

void xqc_packet_out_copy(xqc_packet_out_t *dst, xqc_packet_out_t *src);

xqc_packet_out_t *xqc_packet_out_get(xqc_send_queue_t *send_queue);

xqc_packet_out_t *xqc_packet_out_get_and_insert_send(xqc_send_queue_t *send_queue, enum xqc_pkt_type pkt_type);

void xqc_packet_out_destroy(xqc_packet_out_t *packet_out);

void xqc_maybe_recycle_packet_out(xqc_packet_out_t *packet_out, xqc_connection_t *conn);

xqc_packet_out_t *xqc_write_new_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type);

xqc_packet_out_t *xqc_write_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need);

xqc_packet_out_t *xqc_write_packet_for_stream(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need,
    xqc_stream_t *stream);

int xqc_write_packet_header(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

xqc_int_t xqc_write_ack_or_mp_ack_to_packets(xqc_connection_t *conn);

xqc_int_t xqc_write_ack_or_mp_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, 
    xqc_pkt_num_space_t pns, xqc_path_ctx_t *path, xqc_bool_t is_mp_ack);

int xqc_write_ack_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns);

int xqc_write_ping_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path, 
    void *po_user_data, xqc_bool_t notify, xqc_ping_record_t *pr);

int xqc_write_conn_close_to_packet(xqc_connection_t *conn, uint64_t err_code);

int xqc_write_reset_stream_to_packet(xqc_connection_t *conn, xqc_stream_t *stream, uint64_t err_code, uint64_t final_size);

int xqc_write_stop_sending_to_packet(xqc_connection_t *conn, xqc_stream_t *stream, uint64_t err_code);

int xqc_write_data_blocked_to_packet(xqc_connection_t *conn, uint64_t data_limit);

int xqc_write_stream_data_blocked_to_packet(xqc_connection_t *conn, xqc_stream_id_t stream_id, uint64_t stream_data_limit);

int xqc_write_streams_blocked_to_packet(xqc_connection_t *conn, uint64_t stream_limit, int bidirectional);

int xqc_write_max_data_to_packet(xqc_connection_t *conn, uint64_t max_data);

int xqc_write_max_stream_data_to_packet(xqc_connection_t *conn, 
xqc_stream_id_t stream_id, uint64_t max_stream_data, xqc_pkt_type_t xqc_pkt_type);

int xqc_write_max_streams_to_packet(xqc_connection_t *conn, uint64_t max_stream, int bidirectional);

int xqc_write_new_token_to_packet(xqc_connection_t *conn);

int xqc_write_stream_frame_to_packet(xqc_connection_t *conn, xqc_stream_t *stream, xqc_pkt_type_t pkt_type,
    uint8_t fin, const unsigned char *payload, size_t payload_size, size_t *send_data_written);

int xqc_write_datagram_frame_to_packet(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, 
    const unsigned char *data, size_t data_len, uint64_t *dgram_id, xqc_bool_t use_supplied_dgram_id,
    xqc_data_qos_level_t qos_level);

int xqc_write_handshake_done_frame_to_packet(xqc_connection_t *conn);

xqc_int_t xqc_write_new_conn_id_frame_to_packet(xqc_connection_t *conn, uint64_t retire_prior_to);

xqc_int_t xqc_write_retire_conn_id_frame_to_packet(xqc_connection_t *conn, uint64_t seq_num);

xqc_int_t xqc_write_path_challenge_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path, 
    xqc_bool_t attach_path_status);

xqc_int_t xqc_write_path_response_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path,
    unsigned char *path_response_data);

int xqc_write_ack_mp_to_one_packet(xqc_connection_t *conn, xqc_path_ctx_t *path,
    xqc_packet_out_t *packet_out, xqc_pkt_num_space_t pns);

xqc_int_t xqc_write_path_abandon_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path);

xqc_int_t xqc_write_path_status_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path);

xqc_int_t xqc_write_path_standby_or_available_frame_to_packet(xqc_connection_t *conn, xqc_path_ctx_t *path);

xqc_int_t xqc_write_sid_frame_to_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

xqc_int_t xqc_write_repair_packets(xqc_connection_t *conn, xqc_int_t fss_esi, xqc_list_head_t *prev);

int xqc_write_pmtud_ping_to_packet(xqc_path_ctx_t *path, size_t probing_size, xqc_pkt_type_t pkt_type);

/**
 * @brief Get remained space size in packet out buff.
 * 
 * @param conn 
 * @param po 
 * @return size_t 
 */
size_t xqc_get_po_remained_size(xqc_packet_out_t *po);
size_t xqc_get_po_remained_size_with_ack_spc(xqc_packet_out_t *po);

#endif /* _XQC_PACKET_OUT_H_INCLUDED_ */
