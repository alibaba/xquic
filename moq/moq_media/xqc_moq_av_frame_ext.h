#ifndef _XQC_MOQ_AV_FRAME_EXT_H_INCLUDED_
#define _XQC_MOQ_AV_FRAME_EXT_H_INCLUDED_

#include "moq/xqc_moq.h"
#include "src/common/xqc_list.h"

typedef struct {
    xqc_moq_video_frame_t           video_frame;
    uint64_t                        group_id;
    uint64_t                        object_id;
    xqc_list_head_t                 list_member;
} xqc_moq_video_frame_ext_t;

typedef struct {
    xqc_moq_audio_frame_t           audio_frame;
    uint64_t                        capture_time_ms;
    uint64_t                        recv_time_ms;
    uint64_t                        group_id;
    uint64_t                        object_id;
    xqc_list_head_t                 list_member;
} xqc_moq_audio_frame_ext_t;

void xqc_moq_video_frame_ext_cpy(xqc_moq_video_frame_ext_t *dst_frame,
    xqc_moq_video_frame_ext_t *src_frame);

void xqc_moq_audio_frame_ext_cpy(xqc_moq_audio_frame_ext_t *dst_frame,
    xqc_moq_audio_frame_ext_t *src_frame);

void xqc_moq_video_frame_ext_free(xqc_moq_video_frame_ext_t *frame);

void xqc_moq_audio_frame_ext_free(xqc_moq_audio_frame_ext_t *frame);

#endif /* define _XQC_MOQ_AV_FRAME_EXT_H_INCLUDED_ */
