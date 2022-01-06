/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_FRAME_H_INCLUDED_
#define _XQC_FRAME_H_INCLUDED_

#include <xquic/xquic_typedef.h>

typedef enum {
    XQC_FRAME_PADDING,
    XQC_FRAME_PING,
    XQC_FRAME_ACK,
    XQC_FRAME_RESET_STREAM,
    XQC_FRAME_STOP_SENDING,
    XQC_FRAME_CRYPTO,
    XQC_FRAME_NEW_TOKEN,
    XQC_FRAME_STREAM,
    XQC_FRAME_MAX_DATA,
    XQC_FRAME_MAX_STREAM_DATA,
    XQC_FRAME_MAX_STREAMS,
    XQC_FRAME_DATA_BLOCKED,
    XQC_FRAME_STREAM_DATA_BLOCKED,
    XQC_FRAME_STREAMS_BLOCKED,
    XQC_FRAME_NEW_CONNECTION_ID,
    XQC_FRAME_RETIRE_CONNECTION_ID,
    XQC_FRAME_PATH_CHALLENGE,
    XQC_FRAME_PATH_RESPONSE,
    XQC_FRAME_CONNECTION_CLOSE,
    XQC_FRAME_HANDSHAKE_DONE,
    XQC_FRAME_PATH_STATUS,
    XQC_FRAME_ACK_MP,
    XQC_FRAME_QOE_CONTROL_SIGNAL,
    XQC_FRAME_Extension,
    XQC_FRAME_NUM,
} xqc_frame_type_t;

typedef enum {
    XQC_FRAME_BIT_PADDING               = 1 << XQC_FRAME_PADDING,
    XQC_FRAME_BIT_PING                  = 1 << XQC_FRAME_PING,
    XQC_FRAME_BIT_ACK                   = 1 << XQC_FRAME_ACK,
    XQC_FRAME_BIT_RESET_STREAM          = 1 << XQC_FRAME_RESET_STREAM,
    XQC_FRAME_BIT_STOP_SENDING          = 1 << XQC_FRAME_STOP_SENDING,
    XQC_FRAME_BIT_CRYPTO                = 1 << XQC_FRAME_CRYPTO,
    XQC_FRAME_BIT_NEW_TOKEN             = 1 << XQC_FRAME_NEW_TOKEN,
    XQC_FRAME_BIT_STREAM                = 1 << XQC_FRAME_STREAM,
    XQC_FRAME_BIT_MAX_DATA              = 1 << XQC_FRAME_MAX_DATA,
    XQC_FRAME_BIT_MAX_STREAM_DATA       = 1 << XQC_FRAME_MAX_STREAM_DATA,
    XQC_FRAME_BIT_MAX_STREAMS           = 1 << XQC_FRAME_MAX_STREAMS,
    XQC_FRAME_BIT_DATA_BLOCKED          = 1 << XQC_FRAME_DATA_BLOCKED,
    XQC_FRAME_BIT_STREAM_DATA_BLOCKED   = 1 << XQC_FRAME_STREAM_DATA_BLOCKED,
    XQC_FRAME_BIT_STREAMS_BLOCKED       = 1 << XQC_FRAME_STREAMS_BLOCKED,
    XQC_FRAME_BIT_NEW_CONNECTION_ID     = 1 << XQC_FRAME_NEW_CONNECTION_ID,
    XQC_FRAME_BIT_RETIRE_CONNECTION_ID  = 1 << XQC_FRAME_RETIRE_CONNECTION_ID,
    XQC_FRAME_BIT_PATH_CHALLENGE        = 1 << XQC_FRAME_PATH_CHALLENGE,
    XQC_FRAME_BIT_PATH_RESPONSE         = 1 << XQC_FRAME_PATH_RESPONSE,
    XQC_FRAME_BIT_CONNECTION_CLOSE      = 1 << XQC_FRAME_CONNECTION_CLOSE,
    XQC_FRAME_BIT_HANDSHAKE_DONE        = 1 << XQC_FRAME_HANDSHAKE_DONE,
    XQC_FRAME_BIT_PATH_STATUS           = 1 << XQC_FRAME_PATH_STATUS,
    XQC_FRAME_BIT_ACK_MP                = 1 << XQC_FRAME_ACK_MP,
    XQC_FRAME_BIT_QOE_CONTROL_SIGNAL    = 1 << XQC_FRAME_QOE_CONTROL_SIGNAL,
    XQC_FRAME_BIT_Extension             = 1 << XQC_FRAME_Extension,
    XQC_FRAME_BIT_NUM                   = 1 << XQC_FRAME_NUM,
} xqc_frame_type_bit_t;


/*
 * Ack-eliciting Packet:  A QUIC packet that contains frames other than
      ACK, PADDING, and CONNECTION_CLOSE.  These cause a recipient to
      send an acknowledgment

      Connection close signals, including packets that contain
      CONNECTION_CLOSE frames, are not sent again when packet loss is
      detected, but as described in Section 10.
 */
#define XQC_IS_ACK_ELICITING(types) ((types) & ~(XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_CONNECTION_CLOSE))

/*
 * https://tools.ietf.org/html/draft-ietf-quic-recovery-24#section-3
 * Packets containing frames besides ACK or CONNECTION_CLOSE frames
      count toward congestion control limits and are considered in-
      flight.

   PADDING frames cause packets to contribute toward bytes in flight
      without directly causing an acknowledgment to be sent.
 */
#define XQC_CAN_IN_FLIGHT(types) ((types) & ~(XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_CONNECTION_CLOSE))


/*
 * PING and PADDING frames contain no information, so lost PING or
 *     PADDING frames do not require repair
 */
#define XQC_NEED_REPAIR(types) ((types) & ~(XQC_FRAME_BIT_ACK| XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_PING | XQC_FRAME_BIT_CONNECTION_CLOSE))


const char *xqc_frame_type_2_str(xqc_frame_type_bit_t type_bit);

unsigned int xqc_stream_frame_header_size(xqc_stream_id_t stream_id, uint64_t offset, size_t length);

unsigned int xqc_crypto_frame_header_size(uint64_t offset, size_t length);

xqc_int_t xqc_insert_stream_frame(xqc_connection_t *conn, xqc_stream_t *stream, xqc_stream_frame_t *new_frame);

xqc_int_t xqc_process_frames(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_padding_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_crypto_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_ack_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_ping_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_new_conn_id_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_retire_conn_id_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_conn_close_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_reset_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_stop_sending_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_stream_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_streams_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_max_data_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_max_stream_data_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_max_streams_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_new_token_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_handshake_done_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);


#endif /* _XQC_FRAME_H_INCLUDED_ */
