#ifndef _XQC_MOQ_JITTER_BUFFER_H_INCLUDED_
#define _XQC_MOQ_JITTER_BUFFER_H_INCLUDED_

#include "moq/moq_media/xqc_moq_av_frame_ext.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_time.h"

/* currently, if no decodable frame post after 0.5s, request a keyframe */
#define XQC_MOQ_JITTER_BUFFER_MAX_WAITING_TIME 500000
#define XQC_MOQ_JITTER_BUFFER_MAX_FRAME_SIZE 15

typedef struct xqc_moq_video_frame_buffer_s xqc_moq_video_frame_buffer_t;

typedef struct xqc_moq_jitter_buffer_s {
    xqc_moq_video_frame_buffer_t          *frame_buffer;
    // TODO: add jitter delay moduel
    uint64_t                              last_post_frame_seq_num;
    uint64_t                              last_post_frame_group_id;
    uint64_t                              last_key_frame_seq_num;
    uint64_t                              largest_recv_group_id;
    xqc_log_t                             *log;
    uint32_t                              frame_buf_len;
    uint8_t                               has_posted_frame;
    uint8_t                               requested_key_frame_recv;
} xqc_moq_jitter_buffer_t;

xqc_moq_jitter_buffer_t *xqc_moq_jitter_buffer_create(xqc_log_t *log);

void xqc_moq_jitter_buffer_destroy(xqc_moq_jitter_buffer_t *jitter_buf_inst);

xqc_int_t xqc_moq_jitter_buffer_on_video(xqc_moq_jitter_buffer_t *jitter_buf_inst, 
    xqc_moq_video_frame_ext_t *frame);

xqc_moq_video_frame_ext_t *xqc_moq_jitter_buffer_get_video_frame(
    xqc_moq_jitter_buffer_t *jitter_buf_inst);

void xqc_moq_jitter_buffer_flush(xqc_moq_jitter_buffer_t *jitter_buf_inst);

#endif /* _XQC_MOQ_JITTER_BUFFER_H_INCLUDED_ */