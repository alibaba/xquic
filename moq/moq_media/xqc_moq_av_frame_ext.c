#include "moq/moq_media/xqc_moq_av_frame_ext.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str.h"

void
xqc_moq_video_frame_ext_cpy(xqc_moq_video_frame_ext_t *dst_frame,
    xqc_moq_video_frame_ext_t *src_frame)
{
    xqc_memcpy(dst_frame, src_frame, sizeof(xqc_moq_video_frame_ext_t));
    dst_frame->video_frame.video_data = xqc_malloc(
        dst_frame->video_frame.video_len);
    xqc_memcpy(dst_frame->video_frame.video_data,
        src_frame->video_frame.video_data, dst_frame->video_frame.video_len);
}

void
xqc_moq_audio_frame_ext_cpy(xqc_moq_audio_frame_ext_t *dst_frame,
    xqc_moq_audio_frame_ext_t *src_frame)
{
    xqc_memcpy(dst_frame, src_frame, sizeof(xqc_moq_audio_frame_ext_t));
    dst_frame->audio_frame.audio_data = xqc_malloc(
        dst_frame->audio_frame.audio_len);
    xqc_memcpy(dst_frame->audio_frame.audio_data,
        src_frame->audio_frame.audio_data, dst_frame->audio_frame.audio_len);
}

void
xqc_moq_video_frame_ext_free(xqc_moq_video_frame_ext_t *frame)
{
    xqc_free(frame->video_frame.video_data);
    xqc_free(frame);
}

void
xqc_moq_audio_frame_ext_free(xqc_moq_audio_frame_ext_t *frame)
{
    xqc_free(frame->audio_frame.audio_data);
    xqc_free(frame);
}
