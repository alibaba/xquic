/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_FRAME_PARSER_H_INCLUDED_
#define _XQC_FRAME_PARSER_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_fec.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_recv_timestamps_info.h"

#define XQC_PATH_CHALLENGE_DATA_LEN  8
#define XQC_DATAGRAM_LENGTH_FIELD_BYTES 2
#define XQC_DATAGRAM_HEADER_BYTES (XQC_DATAGRAM_LENGTH_FIELD_BYTES + 1)

#define XQC_TRANS_FRAME_TYPE_MP_ACK0                    0x15228c00
#define XQC_TRANS_FRAME_TYPE_MP_ACK1                    0x15228c01
#define XQC_TRANS_FRAME_TYPE_MP_ABANDON                 0x15228c05
#define XQC_TRANS_FRAME_TYPE_MP_STANDBY                 0x15228c07
#define XQC_TRANS_FRAME_TYPE_MP_AVAILABLE               0x15228c08
#define XQC_TRANS_FRAME_TYPE_MP_NEW_CONN_ID             0x15228c09
#define XQC_TRANS_FRAME_TYPE_MP_RETIRE_CONN_ID          0x15228c0a
#define XQC_TRANS_FRAME_TYPE_MAX_PATH_ID                0x15228c0c
#define XQC_TRANS_FRAME_TYPE_MP_FROZEN                  0x15228cff

#define XQC_TRANS_FRAME_TYPE_ACK_EXT                    0xB1

/**
 * generate datagram frame
 */
xqc_int_t xqc_gen_datagram_frame(xqc_packet_out_t *packet_out, 
    const unsigned char *payload, size_t size);

xqc_int_t xqc_parse_datagram_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn,
    unsigned char **buffer, size_t *size);

/**
 * generate stream frame
 * @param written_size output size of the payload been written
 * @return size of stream frame
 */
ssize_t xqc_gen_stream_frame(xqc_packet_out_t *packet_out,
    xqc_stream_id_t stream_id, uint64_t offset, uint8_t fin,
    const unsigned char *payload, size_t size, size_t *written_size);

xqc_int_t xqc_parse_stream_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn,
    xqc_stream_frame_t *frame, xqc_stream_id_t *stream_id);

ssize_t xqc_gen_crypto_frame(xqc_packet_out_t *packet_out, uint64_t offset,
    const unsigned char *payload, uint64_t payload_size, size_t *written_size);

xqc_int_t xqc_parse_crypto_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn, xqc_stream_frame_t * frame);

void xqc_gen_padding_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

xqc_int_t xqc_gen_padding_frame_with_len(xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    size_t padding_len, size_t limit);

xqc_int_t xqc_parse_padding_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

ssize_t xqc_gen_ping_frame(xqc_packet_out_t *packet_out);

xqc_int_t xqc_parse_ping_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

ssize_t xqc_gen_ack_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_usec_t now, int ack_delay_exponent,
    xqc_recv_record_t *recv_record, xqc_usec_t largest_pkt_recv_time, int *has_gap, xqc_packet_number_t *largest_ack);

xqc_int_t xqc_parse_ack_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn, xqc_ack_info_t *ack_info);

ssize_t xqc_gen_conn_close_frame(xqc_packet_out_t *packet_out, uint64_t err_code, int is_app, int frame_type);

xqc_int_t xqc_parse_conn_close_frame(xqc_packet_in_t *packet_in, uint64_t *err_code, xqc_connection_t *conn);

ssize_t xqc_gen_reset_stream_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id,
    uint64_t err_code, uint64_t final_size);

xqc_int_t xqc_parse_reset_stream_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id,
    uint64_t *err_code, uint64_t *final_size, xqc_connection_t *conn);

ssize_t xqc_gen_stop_sending_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id,
    uint64_t err_code);

xqc_int_t xqc_parse_stop_sending_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id,
    uint64_t *err_code, xqc_connection_t *conn);

ssize_t xqc_gen_data_blocked_frame(xqc_packet_out_t *packet_out, uint64_t data_limit);

xqc_int_t xqc_parse_data_blocked_frame(xqc_packet_in_t *packet_in, uint64_t *data_limit, xqc_connection_t *conn);

ssize_t xqc_gen_stream_data_blocked_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id, uint64_t stream_data_limit);

xqc_int_t xqc_parse_stream_data_blocked_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id, uint64_t *stream_data_limit, xqc_connection_t *conn);

ssize_t xqc_gen_streams_blocked_frame(xqc_packet_out_t *packet_out, uint64_t stream_limit, int bidirectional);

xqc_int_t xqc_parse_streams_blocked_frame(xqc_packet_in_t *packet_in, uint64_t *stream_limit, int *bidirectional, xqc_connection_t *conn);

ssize_t xqc_gen_max_data_frame(xqc_packet_out_t *packet_out, uint64_t max_data);

xqc_int_t xqc_parse_max_data_frame(xqc_packet_in_t *packet_in, uint64_t *max_data, xqc_connection_t *conn);

ssize_t xqc_gen_max_stream_data_frame(xqc_packet_out_t *packet_out, xqc_stream_id_t stream_id, uint64_t max_stream_data);

xqc_int_t xqc_parse_max_stream_data_frame(xqc_packet_in_t *packet_in, xqc_stream_id_t *stream_id, uint64_t *max_stream_data, xqc_connection_t *conn);

ssize_t xqc_gen_max_streams_frame(xqc_packet_out_t *packet_out, uint64_t max_streams, int bidirectional);

xqc_int_t xqc_parse_max_streams_frame(xqc_packet_in_t *packet_in, uint64_t *max_streams, int *bidirectional, xqc_connection_t *conn);

ssize_t xqc_gen_new_token_frame(xqc_packet_out_t *packet_out, const unsigned char *token, unsigned token_len);

xqc_int_t xqc_parse_new_token_frame(xqc_packet_in_t *packet_in, unsigned char *token, unsigned *token_len, xqc_connection_t *conn);

ssize_t xqc_gen_handshake_done_frame(xqc_packet_out_t *packet_out);

xqc_int_t xqc_parse_handshake_done_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn);

ssize_t xqc_gen_new_conn_id_frame(xqc_packet_out_t *packet_out, xqc_cid_t *new_cid,
    uint64_t retire_prior_to, const uint8_t *sr_token);

xqc_int_t xqc_parse_new_conn_id_frame(xqc_packet_in_t *packet_in, xqc_cid_t *new_cid, uint64_t *retire_prior_to, xqc_connection_t *conn);

ssize_t xqc_gen_retire_conn_id_frame(xqc_packet_out_t *packet_out, uint64_t seq_num);

xqc_int_t xqc_parse_retire_conn_id_frame(xqc_packet_in_t *packet_in, uint64_t *seq_num);

ssize_t xqc_gen_path_challenge_frame(xqc_packet_out_t *packet_out, unsigned char *data);

xqc_int_t xqc_parse_path_challenge_frame(xqc_packet_in_t *packet_in, unsigned char *data);

ssize_t xqc_gen_path_response_frame(xqc_packet_out_t *packet_out, unsigned char *data);

xqc_int_t xqc_parse_path_response_frame(xqc_packet_in_t *packet_in, unsigned char *data);

ssize_t xqc_gen_ack_mp_frame(xqc_connection_t *conn, uint64_t path_id, xqc_packet_out_t *packet_out, xqc_usec_t now, 
    int ack_delay_exponent, xqc_recv_record_t *recv_record, xqc_usec_t largest_pkt_recv_time, int *has_gap, xqc_packet_number_t *largest_ack);

xqc_int_t xqc_parse_ack_mp_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn,
    uint64_t *path_id, xqc_ack_info_t *ack_info);

ssize_t xqc_gen_path_abandon_frame(xqc_connection_t *conn, 
    xqc_packet_out_t *packet_out, uint64_t path_id, uint64_t error_code);

xqc_int_t xqc_parse_path_abandon_frame(xqc_packet_in_t *packet_in,
    uint64_t *path_id, uint64_t *error_code);

ssize_t xqc_gen_path_status_frame(xqc_connection_t *conn,
    xqc_packet_out_t *packet_out,
    uint64_t path_id,
    uint64_t path_status_seq_num,
    xqc_app_path_status_t status);

xqc_int_t xqc_parse_path_status_frame(xqc_packet_in_t *packet_in,
    uint64_t *path_id,
    uint64_t *path_status_seq_num, uint64_t *path_status); 

ssize_t xqc_gen_sid_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

xqc_int_t xqc_parse_sid_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in, uint64_t *src_payload_id, xqc_int_t *symbol_size);

xqc_int_t xqc_gen_repair_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_int_t fss_esi,
    xqc_int_t repair_idx, uint8_t bm_idx);

xqc_int_t xqc_parse_repair_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in,
    xqc_fec_rpr_syb_t *rpr_symbol);

ssize_t xqc_gen_mp_new_conn_id_frame(xqc_packet_out_t *packet_out, xqc_cid_t *new_cid,
    uint64_t retire_prior_to, const uint8_t *sr_token, uint64_t path_id);

xqc_int_t xqc_parse_mp_new_conn_id_frame(xqc_packet_in_t *packet_in,
    xqc_cid_t *new_cid, uint64_t *retire_prior_to, uint64_t *path_id, xqc_connection_t *conn);

ssize_t xqc_gen_mp_retire_conn_id_frame(xqc_packet_out_t *packet_out, uint64_t seq_num, uint64_t path_id);

xqc_int_t xqc_parse_mp_retire_conn_id_frame(xqc_packet_in_t *packet_in, uint64_t *seq_num, uint64_t *path_id);

ssize_t xqc_gen_max_path_id_frame(xqc_packet_out_t *packet_out, uint64_t max_path_id);
xqc_int_t xqc_parse_max_path_id_frame(xqc_packet_in_t *packet_in, uint64_t *max_path_id);

void xqc_try_process_fec_decode(xqc_connection_t *conn, xqc_int_t block_id);


void xqc_get_lack_src_syb(unsigned char* pm, unsigned char* recv_mask, xqc_int_t m_size,
    uint8_t *syb_idx, uint8_t *syb_num);

ssize_t xqc_gen_ack_ext_frame(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_usec_t now,
    int ack_delay_exponent, xqc_recv_record_t *recv_record, xqc_usec_t largest_pkt_recv_time, int *has_gap, 
    xqc_packet_number_t *largest_ack, xqc_recv_timestamps_info_t *recv_ts_info);

xqc_int_t xqc_parse_ack_ext_frame(xqc_packet_in_t *packet_in, xqc_connection_t *conn,
    xqc_ack_info_t *ack_info, xqc_ack_timestamp_info_t *ack_ts_info);

#endif /*_XQC_FRAME_PARSER_H_INCLUDED_*/
