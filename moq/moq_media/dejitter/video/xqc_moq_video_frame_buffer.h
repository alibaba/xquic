#ifndef XQC_MOQ_VIDEO_FRAME_BUFFER_H_INCLUDED_
#define XQC_MOQ_VIDEO_FRAME_BUFFER_H_INCLUDED_

#include "include/xquic/xquic_typedef.h"
#include "moq/moq_media/xqc_moq_av_frame_ext.h"
#include "src/common/xqc_list.h"

typedef struct xqc_moq_video_frame_buffer_s {
    xqc_list_head_t                   list;
    uint64_t                          last_continuous_pid;
    uint32_t                          buf_len;
} xqc_moq_video_frame_buffer_t;

xqc_moq_video_frame_buffer_t *xqc_moq_video_frame_buffer_create();

void xqc_moq_video_frame_buffer_flush(xqc_moq_video_frame_buffer_t *frame_buf_inst);

xqc_int_t xqc_moq_video_frame_buffer_insert(
    xqc_moq_video_frame_buffer_t *frame_buf_inst,
    xqc_moq_video_frame_ext_t *in_frame);

xqc_moq_video_frame_ext_t* xqc_moq_video_frame_buffer_get_video(
    xqc_moq_video_frame_buffer_t *frame_buf_inst);

#endif /* XQC_MOQ_VIDEO_FRAME_BUFFER_H_INCLUDED_ */