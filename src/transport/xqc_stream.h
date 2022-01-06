/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_STREAM_H_INCLUDED_
#define _XQC_STREAM_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/common/xqc_list.h"
#include "src/transport/xqc_packet.h"

#define XQC_UNDEFINE_STREAM_ID XQC_MAX_UINT64_VALUE

typedef enum {
    XQC_CLI_BID = 0,
    XQC_SVR_BID = 1,
    XQC_CLI_UNI = 2,
    XQC_SVR_UNI = 3,
} xqc_stream_type_t;


typedef enum {
    XQC_STREAM_FLAG_READY_TO_WRITE  = 1 << 0,
    XQC_STREAM_FLAG_READY_TO_READ   = 1 << 1,
    XQC_STREAM_FLAG_DATA_BLOCKED    = 1 << 2,
    XQC_STREAM_FLAG_HAS_0RTT        = 1 << 3,
    XQC_STREAM_FLAG_HAS_H3          = 1 << 4,
    XQC_STREAM_FLAG_NEED_CLOSE      = 1 << 5,
    XQC_STREAM_FLAG_FIN_WRITE       = 1 << 6,
    XQC_STREAM_FLAG_CLOSED          = 1 << 7,
} xqc_stream_flag_t;

typedef enum {
    XQC_SEND_STREAM_ST_READY,
    XQC_SEND_STREAM_ST_SEND,
    XQC_SEND_STREAM_ST_DATA_SENT,
    XQC_SEND_STREAM_ST_DATA_RECVD,
    XQC_SEND_STREAM_ST_RESET_SENT,
    XQC_SEND_STREAM_ST_RESET_RECVD,
} xqc_send_stream_state_t;

typedef enum {
    XQC_RECV_STREAM_ST_RECV,
    XQC_RECV_STREAM_ST_SIZE_KNOWN,
    XQC_RECV_STREAM_ST_DATA_RECVD,
    XQC_RECV_STREAM_ST_DATA_READ,
    XQC_RECV_STREAM_ST_RESET_RECVD,
    XQC_RECV_STREAM_ST_RESET_READ,
} xqc_recv_stream_state_t;

typedef struct {
    uint64_t                fc_max_stream_data_can_send;
    uint64_t                fc_max_stream_data_can_recv;
    uint64_t                fc_stream_recv_window_size;
    xqc_usec_t              fc_last_window_update_time;
} xqc_stream_flow_ctl_t;


/* Put one STREAM frame */
typedef struct xqc_stream_frame_s {
    xqc_list_head_t         sf_list;
    unsigned char          *data;
    unsigned                data_length;
    uint64_t                data_offset;
    uint64_t                next_read_offset;   /* next offset in frame */
    unsigned char           fin;
} xqc_stream_frame_t;


/* Put all received STREAM data here */
typedef struct xqc_stream_data_in_s {
    /* A list of STREAM frame, order by offset */
    xqc_list_head_t         frames_tailq;       /* xqc_stream_frame_t */
    uint64_t                merged_offset_end;  /* [0,end) */
    uint64_t                next_read_offset;   /* next offset in stream */
    uint64_t                stream_length;
} xqc_stream_data_in_t;


typedef struct xqc_stream_write_buff_s {
    xqc_list_head_t         sw_list;
    unsigned char          *sw_data;
    unsigned                data_length;
    uint64_t                data_offset;
    uint64_t                next_write_offset;
    unsigned char           fin;
} xqc_stream_write_buff_t;

typedef struct xqc_stream_write_buff_list_s {
    xqc_list_head_t         write_buff_list; /* xqc_stream_write_buff_t */
    uint64_t                next_write_offset;
    uint64_t                total_len;
} xqc_stream_write_buff_list_t;

struct xqc_stream_s {
    xqc_connection_t       *stream_conn;
    xqc_stream_id_t         stream_id;
    xqc_stream_type_t       stream_type;
    void                   *user_data;
    xqc_stream_callbacks_t *stream_if;

    xqc_stream_flow_ctl_t   stream_flow_ctl;
    xqc_stream_write_buff_list_t
                            stream_write_buff_list; /* buffer list for 0RTT */
    xqc_list_head_t         write_stream_list,
                            read_stream_list,
                            closing_stream_list,
                            all_stream_list;

    uint64_t                stream_send_offset;
    uint64_t                stream_max_recv_offset;
    xqc_stream_flag_t       stream_flag;
    xqc_encrypt_level_t     stream_encrypt_level;
    xqc_stream_data_in_t    stream_data_in;
    unsigned                stream_unacked_pkt;
    int64_t                 stream_refcnt;
    xqc_send_stream_state_t stream_state_send;
    xqc_recv_stream_state_t stream_state_recv;
    xqc_usec_t              stream_close_time;
    uint64_t                stream_err;

    struct {
        xqc_usec_t          create_time;
        xqc_usec_t          peer_fin_rcv_time;      /* quic stack rcv fin */
        xqc_usec_t          peer_fin_read_time;     /* app read fin */
        xqc_usec_t          local_fin_write_time;   /* app send fin */
        xqc_usec_t          local_fin_snd_time;     /* socket send fin */
        xqc_usec_t          first_write_time;       /* app send data */
        xqc_usec_t          first_snd_time;         /* socket send data */
        xqc_usec_t          first_fin_ack_time;
        xqc_usec_t          all_data_acked_time;
        xqc_usec_t          close_time;             /* stream close time: fin/reset read */
        xqc_usec_t          app_reset_time;         /* app snd reset */
        xqc_usec_t          local_reset_time;       /* socket snd reset */
        xqc_usec_t          peer_reset_time;        /* quic stack rcv reset */
    } stream_stats;
};

static inline xqc_stream_type_t
xqc_get_stream_type(xqc_stream_id_t stream_id)
{
    return stream_id & 0x03;
}

static inline xqc_int_t
xqc_stream_is_bidi(xqc_stream_id_t stream_id)
{
    return stream_id == 0x00 || !(stream_id & 0x02);
}

static inline xqc_int_t
xqc_stream_is_uni(xqc_stream_id_t stream_id)
{
    return stream_id & 0x02;
}

xqc_stream_t *xqc_create_stream_with_conn (xqc_connection_t *conn, xqc_stream_id_t stream_id,
    xqc_stream_type_t stream_type, void *user_data);

void xqc_destroy_stream(xqc_stream_t *stream);

void xqc_process_write_streams(xqc_connection_t *conn);

void xqc_process_read_streams(xqc_connection_t *conn);

void xqc_process_crypto_write_streams(xqc_connection_t *conn);

void xqc_process_crypto_read_streams(xqc_connection_t *conn);

void xqc_stream_ready_to_write(xqc_stream_t *stream);

void xqc_stream_shutdown_write(xqc_stream_t *stream);

void xqc_stream_ready_to_read(xqc_stream_t *stream);

void xqc_stream_shutdown_read(xqc_stream_t *stream);

void xqc_stream_maybe_need_close(xqc_stream_t *stream);

xqc_stream_t *xqc_find_stream_by_id(xqc_stream_id_t stream_id, xqc_id_hash_table_t *streams_hash);

void xqc_stream_set_flow_ctl(xqc_stream_t *stream);

int xqc_stream_do_send_flow_ctl(xqc_stream_t *stream);

int xqc_stream_do_recv_flow_ctl(xqc_stream_t *stream);

int xqc_stream_do_create_flow_ctl(xqc_connection_t *conn, xqc_stream_id_t stream_id, xqc_stream_type_t stream_type);

uint64_t xqc_stream_get_init_max_stream_data(xqc_stream_t *stream);

xqc_stream_t* xqc_passive_create_stream(xqc_connection_t *conn, xqc_stream_id_t stream_id, void *user_data);

xqc_stream_t* xqc_create_crypto_stream(xqc_connection_t *conn, xqc_encrypt_level_t encrypt_level, void *user_data);

int xqc_crypto_stream_on_write(xqc_stream_t *stream, void *user_data);

int xqc_read_crypto_stream(xqc_stream_t *stream);

ssize_t xqc_stream_buff_data(xqc_stream_t *stream, unsigned char *send_data, size_t send_data_size, uint8_t fin);

int xqc_stream_write_buffed_data_to_packets(xqc_stream_t *stream);

void xqc_destroy_stream_frame(xqc_stream_frame_t *stream_frame);

void xqc_destroy_write_buff(xqc_stream_write_buff_t *write_buff);

void xqc_destroy_frame_list(xqc_list_head_t *head);

void xqc_destroy_write_buff_list(xqc_list_head_t *head);

void xqc_stream_refcnt_add(xqc_stream_t *stream);
void xqc_stream_refcnt_del(xqc_stream_t *stream);

void
xqc_stream_send_state_update(xqc_stream_t *stream, xqc_send_stream_state_t state);

void
xqc_stream_recv_state_update(xqc_stream_t *stream, xqc_recv_stream_state_t state);


#endif /* _XQC_STREAM_H_INCLUDED_ */

