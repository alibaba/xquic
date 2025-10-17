#include "src/common/xqc_malloc.h"
#include "moq/moq_media/dejitter/video/xqc_moq_jitter_buffer.h"
#include "moq/moq_media/dejitter/video/xqc_moq_video_frame_buffer.h"

xqc_moq_jitter_buffer_t *
xqc_moq_jitter_buffer_create(xqc_log_t *log)
{
    xqc_moq_jitter_buffer_t *jitter_buf_inst = 
        xqc_calloc(1, sizeof(xqc_moq_jitter_buffer_t));
    jitter_buf_inst->frame_buffer = xqc_moq_video_frame_buffer_create();
    jitter_buf_inst->log = log;
    return jitter_buf_inst;
}

void
xqc_moq_jitter_buffer_flush(xqc_moq_jitter_buffer_t *jitter_buf_inst)
{
    xqc_moq_video_frame_buffer_flush(jitter_buf_inst->frame_buffer);
    jitter_buf_inst->frame_buf_len = 0;
}

void
xqc_moq_jitter_buffer_destroy(xqc_moq_jitter_buffer_t *jitter_buf_inst)
{
    xqc_moq_jitter_buffer_flush(jitter_buf_inst);
    xqc_free(jitter_buf_inst->frame_buffer);
    xqc_free(jitter_buf_inst);
}

xqc_int_t
xqc_moq_jitter_buffer_insert_frame(xqc_moq_jitter_buffer_t *jitter_buf_inst,
    xqc_moq_video_frame_ext_t *frame)
{
    xqc_moq_video_frame_ext_t *in_frame = xqc_malloc(
        sizeof(xqc_moq_video_frame_ext_t));
    xqc_moq_video_frame_ext_cpy(in_frame, frame);
    int ret = xqc_moq_video_frame_buffer_insert(jitter_buf_inst->frame_buffer,
                                                  in_frame);
    if (ret < 0) {
        // if insert fail, free mem.
        // TODO: after make sure the frame could be inserted, memcpy it.
        xqc_moq_video_frame_ext_free(in_frame);
    }
    jitter_buf_inst->frame_buf_len = jitter_buf_inst->frame_buffer->buf_len;
    return ret;
}

xqc_moq_video_frame_ext_t *
xqc_moq_jitter_buffer_get_video_frame(xqc_moq_jitter_buffer_t *jitter_buf_inst)
{
    xqc_moq_video_frame_ext_t *out_frame = xqc_moq_video_frame_buffer_get_video(
        jitter_buf_inst->frame_buffer);
    jitter_buf_inst->frame_buf_len = jitter_buf_inst->frame_buffer->buf_len;
    if (out_frame != NULL) {
        jitter_buf_inst->has_posted_frame = 1;
        jitter_buf_inst->last_post_frame_seq_num = out_frame->video_frame.seq_num;
        jitter_buf_inst->last_post_frame_group_id = out_frame->group_id;
    }
    return out_frame;
}

xqc_int_t
xqc_moq_jitter_buffer_on_video(xqc_moq_jitter_buffer_t *jitter_buf_inst, 
    xqc_moq_video_frame_ext_t *frame)
{
    if (jitter_buf_inst->has_posted_frame) {
        if (frame->group_id < jitter_buf_inst->last_post_frame_group_id) {
            xqc_log(jitter_buf_inst->log, XQC_LOG_INFO,
                "|Old frame group arrival|group_id: %ui|", frame->group_id);
            return -1;
        } else if (frame->group_id == jitter_buf_inst->last_post_frame_group_id &&
            frame->video_frame.seq_num <= jitter_buf_inst->last_post_frame_seq_num)
        {
            xqc_log(jitter_buf_inst->log, XQC_LOG_INFO,
                "|Old frame seq arrival|seq_num: %ui|", frame->video_frame.seq_num);
            return -1;
        }
    }
    if (frame->video_frame.type == XQC_MOQ_VIDEO_KEY) {
        jitter_buf_inst->last_key_frame_seq_num = frame->video_frame.seq_num;
        jitter_buf_inst->requested_key_frame_recv = 1;
    }
    if (frame->group_id > jitter_buf_inst->largest_recv_group_id) {
        jitter_buf_inst->largest_recv_group_id = frame->group_id;
    }
    return xqc_moq_jitter_buffer_insert_frame(jitter_buf_inst, frame);
}