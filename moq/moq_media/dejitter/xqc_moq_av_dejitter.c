#include "src/common/xqc_malloc.h"
#include "moq/moq_media/dejitter/xqc_moq_av_dejitter.h"
// #include "moq/moq_media/audio/neteq/xqc_moq_neteq.h"
#include "moq/moq_media/dejitter/video/xqc_moq_jitter_buffer.h"

static xqc_bool_t 
xqc_moq_av_dejitter_requested_keyframe(
    xqc_moq_av_dejitter_t *dejitter)
{
    if (!dejitter->video_jitter_buffer->requested_key_frame_recv) {
        return 0;
    } else {
        dejitter->video_jitter_buffer->requested_key_frame_recv = 0;
        return 1;
    }
}

static void
xqc_moq_video_dejitter_timer_timeout(xqc_gp_timer_id_t timer_id,
    xqc_usec_t now, void *user_data)
{
    xqc_moq_av_dejitter_t *dejitter = (xqc_moq_av_dejitter_t*)user_data;
    xqc_log(dejitter->log, XQC_LOG_DEBUG, "|request key frame|");
    /* 
    *  only after receiving the requested keyframe,
    *  client could request another keyframe
    */
    if (xqc_moq_av_dejitter_requested_keyframe(dejitter)) {
        uint64_t largest_group_id = 
            dejitter->video_jitter_buffer->largest_recv_group_id;
        dejitter->request_keyframe(dejitter->user_data);
    }
}

xqc_moq_av_dejitter_t *
xqc_moq_av_dejitter_create(xqc_bool_t is_video_track, 
    xqc_timer_manager_t *time_manager, int audio_sample_rate_hz,
    void *log, void *media_track)
{
    xqc_moq_av_dejitter_t *dejitter = 
        xqc_calloc(1, sizeof(xqc_moq_av_dejitter_t));
    dejitter->timer_manager = time_manager;
    dejitter->log = log;
    dejitter->user_data = media_track;
    if (is_video_track) {
        dejitter->video_jitter_buffer = xqc_moq_jitter_buffer_create(log);
        dejitter->timer_id = xqc_timer_register_gp_timer(
                                            dejitter->timer_manager,
                                            "key_frame_req_timer", 
                                            xqc_moq_video_dejitter_timer_timeout,
                                            dejitter);
    } else {
        xqc_log(dejitter->log, XQC_LOG_INFO, "|disable audio currently|");
        dejitter->audio_neteq = NULL;
    }
    return dejitter;
}

void 
xqc_moq_av_dejitter_on_video(xqc_moq_av_dejitter_t *dejitter,
    xqc_moq_video_frame_ext_t *frame)
{
    int ret = xqc_moq_jitter_buffer_on_video(dejitter->video_jitter_buffer, frame);
    if (ret < 0) {
        xqc_log(dejitter->log, XQC_LOG_INFO,
            "|Invalid video frame|error: %d|", ret);
    } else {
        xqc_moq_video_frame_ext_t *decodable_frame = NULL;
        int key_frame_req_interval = -1;
        while (1) {
            decodable_frame = xqc_moq_jitter_buffer_get_video_frame(
                                            dejitter->video_jitter_buffer);
            if (decodable_frame == NULL) {
                break;
            }
            key_frame_req_interval = XQC_MOQ_JITTER_BUFFER_MAX_WAITING_TIME;
            dejitter->on_decodable_video_frame(decodable_frame,
                                               dejitter->user_data);
            xqc_moq_video_frame_ext_free(decodable_frame);
            decodable_frame = NULL;
        }
        if (dejitter->video_jitter_buffer->frame_buf_len >
            XQC_MOQ_JITTER_BUFFER_MAX_FRAME_SIZE)
        {
            key_frame_req_interval = 1000;
            // if the buf len is greater than max_size, flush it immediately.
            xqc_moq_jitter_buffer_flush(dejitter->video_jitter_buffer);
        }
        if (key_frame_req_interval > 0) {
            xqc_log(dejitter->log, XQC_LOG_DEBUG,
                "|key_frame_req_interval:%d|", key_frame_req_interval);
            xqc_usec_t expire_time = 
                            xqc_monotonic_timestamp() + key_frame_req_interval;
            xqc_timer_gp_timer_set(dejitter->timer_manager,
                                   dejitter->timer_id, expire_time);
        }
    }
}

void
xqc_moq_av_dejitter_destroy(xqc_moq_av_dejitter_t *av_dejitter)
{
    if (av_dejitter->audio_neteq != NULL) {
        xqc_log(av_dejitter->log, XQC_LOG_ERROR,
            "|disable audio currently, audio_neteq should always be NULL|");
    }
    if (av_dejitter->video_jitter_buffer != NULL) {
        xqc_moq_jitter_buffer_destroy(av_dejitter->video_jitter_buffer);
    }
    if (av_dejitter->timer_manager != NULL) {
        xqc_timer_unregister_gp_timer(av_dejitter->timer_manager,
                                      av_dejitter->timer_id);
    }
    xqc_free(av_dejitter);
}

uint64_t
xqc_moq_av_dejitter_get_largest_video_group_id(xqc_moq_av_dejitter_t *dejitter)
{
    if (dejitter->video_jitter_buffer == NULL) {
        xqc_log(dejitter->log, XQC_LOG_ERROR, "|video_jitter_buffer is NULL");
        return 0;
    }
    return dejitter->video_jitter_buffer->largest_recv_group_id;
}