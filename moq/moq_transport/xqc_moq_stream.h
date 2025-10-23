#ifndef _XQC_MOQ_STREAM_H_INCLUDED_
#define _XQC_MOQ_STREAM_H_INCLUDED_

#include "moq/xqc_moq.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_fec.h"

typedef struct {
    void *(*create)(void *conn, xqc_stream_direction_t dir, void *user_data);
    xqc_stream_t *(*quic_stream)(void *stream);
    ssize_t (*write)(void *stream, uint8_t *send_data, size_t send_data_size, uint8_t fin);
    xqc_int_t (*close)(void *stream);
} xqc_moq_trans_stream_ops_t;

/** defined for uint16_t moq_frame_type in structure xqc_moq_stream_t */
typedef enum {
    MOQ_VIDEO_FRAME,
    MOQ_AUDIO_FRAME
} xqc_moq_frame_type_t;


typedef struct xqc_moq_stream_s {
    xqc_moq_session_t           *session;
    void                        *trans_stream; /* Depend on transport type */
    xqc_moq_trans_stream_ops_t  trans_ops;
    union {
        xqc_moq_stream_header_track_msg_t track_header;
        xqc_moq_stream_header_group_msg_t group_header;
    };

    uint8_t                     *read_buf;
    size_t                      read_buf_cap;
    size_t                      read_buf_len;
    size_t                      read_buf_processed;
    uint8_t                     remain_read_buf[8];
    size_t                      remain_read_buf_len;
    xqc_moq_decode_msg_ctx_t    decode_msg_ctx;

    uint8_t                     *write_buf;
    size_t                      write_buf_cap;
    size_t                      write_buf_len;
    size_t                      write_buf_processed;
    uint8_t                     write_stream_fin;

    xqc_moq_track_t             *track;
    xqc_list_head_t             list_member; /* track write_stream_list */
    uint64_t                    group_id;
    uint64_t                    object_id;
    uint64_t                    seq_num;

    xqc_flag_t                  enable_fec;
    float                       fec_code_rate;

    uint16_t                    moq_frame_type;
} xqc_moq_stream_t;

xqc_moq_stream_t *xqc_moq_stream_create(xqc_moq_session_t *session);

void xqc_moq_stream_destroy(xqc_moq_stream_t *moq_stream);

xqc_moq_stream_t *xqc_moq_stream_create_with_transport(xqc_moq_session_t *session, xqc_stream_direction_t direction);

xqc_int_t xqc_moq_stream_close(xqc_moq_stream_t *moq_stream);

xqc_int_t xqc_moq_stream_write(xqc_moq_stream_t *moq_stream);

void xqc_moq_stream_on_track_write(xqc_moq_stream_t *moq_stream, xqc_moq_track_t *track,
    uint64_t group_id, uint64_t object_id, uint64_t seq_num);

void *xqc_moq_stream_get_or_alloc_cur_decode_msg(xqc_moq_stream_t *moq_stream);

void xqc_moq_stream_free_cur_decode_msg(xqc_moq_stream_t *moq_stream);

void xqc_moq_stream_clean_decode_msg_ctx(xqc_moq_stream_t *moq_stream);

xqc_int_t xqc_moq_stream_process(xqc_moq_stream_t *moq_stream, uint8_t *buf, size_t buf_len, uint8_t fin);

xqc_int_t xqc_moq_stream_process_msg(xqc_moq_stream_t *moq_stream, uint8_t stream_fin,
    xqc_int_t *msg_finish, xqc_int_t *wait_more_data);

#endif /* _XQC_MOQ_STREAM_H_INCLUDED_ */
