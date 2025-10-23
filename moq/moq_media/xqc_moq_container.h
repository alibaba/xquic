#ifndef _XQC_MOQ_CONTAINER_H_INCLUDED_
#define _XQC_MOQ_CONTAINER_H_INCLUDED_

#include "moq/xqc_moq.h"

#define XQC_MOQ_CONTAINER_LOC_STR       "loc"
#define XQC_MOQ_CONTAINER_CMAF_STR      "cmaf"

#define XQC_MOQ_MAX_CONTAINER_OVERHEAD  200

typedef struct xqc_moq_media_container_ops_s {
    xqc_int_t (*encode_video)(xqc_moq_video_frame_t *video_frame,
                              uint8_t *buf, size_t buf_cap, xqc_int_t *encoded_len);
    xqc_int_t (*decode_video)(uint8_t *buf, xqc_int_t len, xqc_moq_video_frame_t *video_frame);
    xqc_int_t (*encode_audio)(xqc_moq_audio_frame_t *audio_frame,
                              uint8_t *buf, size_t buf_cap, xqc_int_t *encoded_len);
    xqc_int_t (*decode_audio)(uint8_t *buf, xqc_int_t len, xqc_moq_audio_frame_t *audio_frame);
} xqc_moq_media_container_ops_t;

#endif /* _XQC_MOQ_CONTAINER_H_INCLUDED_ */
