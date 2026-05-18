#include "moq/moq_media/xqc_moq_av_frame_ext.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str.h"

void
xqc_moq_video_frame_ext_cpy(xqc_moq_video_frame_ext_t *dst_frame,
    xqc_moq_video_frame_ext_t *src_frame)
{
    xqc_memcpy(dst_frame, src_frame, sizeof(xqc_moq_video_frame_ext_t));
    dst_frame->video_frame.video_data = NULL;
    dst_frame->video_frame.video_config = NULL;
    dst_frame->video_frame.bizinfo = NULL;

    if (src_frame->video_frame.video_len > 0 &&
        src_frame->video_frame.video_data != NULL)
    {
        dst_frame->video_frame.video_data = xqc_malloc(
            dst_frame->video_frame.video_len);
        xqc_memcpy(dst_frame->video_frame.video_data,
            src_frame->video_frame.video_data,
            dst_frame->video_frame.video_len);
    }

    if (src_frame->video_frame.has_video_config &&
        src_frame->video_frame.video_config_len > 0 &&
        src_frame->video_frame.video_config != NULL)
    {
        dst_frame->video_frame.video_config = xqc_malloc(
            dst_frame->video_frame.video_config_len);
        xqc_memcpy(dst_frame->video_frame.video_config,
            src_frame->video_frame.video_config,
            dst_frame->video_frame.video_config_len);
    }

    if (src_frame->video_frame.has_bizinfo &&
        src_frame->video_frame.bizinfo_len > 0 &&
        src_frame->video_frame.bizinfo != NULL)
    {
        dst_frame->video_frame.bizinfo = xqc_malloc(
            dst_frame->video_frame.bizinfo_len);
        xqc_memcpy(dst_frame->video_frame.bizinfo,
            src_frame->video_frame.bizinfo,
            dst_frame->video_frame.bizinfo_len);
    }
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
    if (frame == NULL) {
        return;
    }
    if (frame->video_frame.video_data) {
        xqc_free(frame->video_frame.video_data);
        frame->video_frame.video_data = NULL;
    }
    if (frame->video_frame.video_config) {
        xqc_free(frame->video_frame.video_config);
        frame->video_frame.video_config = NULL;
    }
    if (frame->video_frame.bizinfo) {
        xqc_free(frame->video_frame.bizinfo);
        frame->video_frame.bizinfo = NULL;
    }
    xqc_free(frame);
}

void
xqc_moq_audio_frame_ext_free(xqc_moq_audio_frame_ext_t *frame)
{
    xqc_free(frame->audio_frame.audio_data);
    xqc_free(frame);
}
