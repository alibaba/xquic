#include "moq/moq_media/dejitter/video/xqc_moq_video_frame_buffer.h"
#include "src/common/xqc_malloc.h"

xqc_moq_video_frame_buffer_t *
xqc_moq_video_frame_buffer_create()
{
    xqc_moq_video_frame_buffer_t *frame_buf =
        xqc_calloc(1, sizeof(xqc_moq_video_frame_buffer_t));
    xqc_init_list_head(&frame_buf->list);
    return frame_buf;
}

void
xqc_moq_video_frame_buffer_flush(xqc_moq_video_frame_buffer_t *frame_buf_inst)
{
    if (xqc_list_empty(&frame_buf_inst->list)) {
        return;
    }
    xqc_list_head_t *pos, *next;
    xqc_moq_video_frame_ext_t *cur_frame;
    xqc_list_for_each_safe(pos, next, &frame_buf_inst->list) {
        cur_frame = xqc_list_entry(pos, xqc_moq_video_frame_ext_t, list_member);
        xqc_list_del(pos);
        xqc_moq_video_frame_ext_free(cur_frame);
    }
    frame_buf_inst->buf_len = 0;
}

xqc_int_t
xqc_moq_video_frame_buffer_insert(xqc_moq_video_frame_buffer_t *frame_buf_inst,
    xqc_moq_video_frame_ext_t *in_frame)
{
    if (xqc_list_empty(&frame_buf_inst->list)) {
        xqc_list_add(&in_frame->list_member, &frame_buf_inst->list);
        frame_buf_inst->buf_len += 1;
        return 0;
    }
    xqc_list_head_t *pos, *next;
    xqc_moq_video_frame_ext_t *cur_frame;
    xqc_list_for_each_reverse_safe(pos, next, &frame_buf_inst->list) {
        cur_frame = xqc_list_entry(pos, xqc_moq_video_frame_ext_t, list_member);
        if (cur_frame->video_frame.seq_num == in_frame->video_frame.seq_num) {
            return -3;
        } else if (cur_frame->video_frame.seq_num < in_frame->video_frame.seq_num) {
            break;
        }
    }
    xqc_list_add(&in_frame->list_member, pos);
    frame_buf_inst->buf_len += 1;
    // if recv a key frame, flush all frames before it;
    if (in_frame->video_frame.type == XQC_MOQ_VIDEO_KEY) {
        xqc_list_for_each_safe(pos, next, &frame_buf_inst->list) {
            if(pos == &in_frame->list_member) {
                break;
            }
            cur_frame = xqc_list_entry(pos, xqc_moq_video_frame_ext_t, list_member);
            xqc_list_del(pos);
            frame_buf_inst->buf_len -= 1;
            xqc_moq_video_frame_ext_free(cur_frame);
        }
    }
    return 0;
}

xqc_moq_video_frame_ext_t*
xqc_moq_frame_buffer_get_next_frame(xqc_moq_video_frame_buffer_t *frame_buf_inst)
{
    if (xqc_list_empty(&frame_buf_inst->list)) {
        return NULL;
    }
    xqc_list_head_t *pos = frame_buf_inst->list.next;
    xqc_list_del(pos);
    frame_buf_inst->buf_len -= 1;
    xqc_moq_video_frame_ext_t *cur_frame =
        xqc_list_entry(pos, xqc_moq_video_frame_ext_t, list_member);
    return cur_frame;
}

xqc_bool_t
xqc_moq_video_frame_buffer_decodable_check(
    xqc_moq_video_frame_buffer_t *frame_buf_inst)
{
    if (xqc_list_empty(&frame_buf_inst->list)) {
        return 0;
    }
    xqc_list_head_t *pos = frame_buf_inst->list.next;
    xqc_moq_video_frame_ext_t *cur_frame =
        xqc_list_entry(pos, xqc_moq_video_frame_ext_t, list_member);
    
    if ((cur_frame->video_frame.type == XQC_MOQ_VIDEO_KEY)
        || (cur_frame->video_frame.seq_num == 
            frame_buf_inst->last_continuous_pid + 1))
    {
        frame_buf_inst->last_continuous_pid = cur_frame->video_frame.seq_num;
        return 1;
    }
    return 0;
}

xqc_moq_video_frame_ext_t* 
xqc_moq_video_frame_buffer_get_video(xqc_moq_video_frame_buffer_t *frame_buf_inst)
{
    if (!xqc_moq_video_frame_buffer_decodable_check(frame_buf_inst)) {
        return NULL;
    }
    xqc_moq_video_frame_ext_t* frame_out = xqc_moq_frame_buffer_get_next_frame(
                                                frame_buf_inst);
    return frame_out;
}
