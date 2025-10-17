#ifndef _XQC_MOQ_AV_DEJITTER_H_INCLUDED_
#define _XQC_MOQ_AV_DEJITTER_H_INCLUDED_

#include "moq/moq_media/xqc_moq_av_frame_ext.h"
#include "src/transport/xqc_timer.h"
#include "src/common/xqc_log.h"

typedef struct xqc_moq_neteq_s              xqc_moq_neteq_t;
typedef struct xqc_moq_jitter_buffer_s      xqc_moq_jitter_buffer_t;
    
typedef void (*xqc_moq_on_decodable_video_frame_pt)
    (xqc_moq_video_frame_ext_t *frame, void *track_user_date);

typedef void (*xqc_moq_request_keyframe_pt)(void *track_user_date);

typedef struct xqc_moq_av_dejitter_s {
    xqc_moq_neteq_t                                 *audio_neteq;
    xqc_moq_jitter_buffer_t                         *video_jitter_buffer;
    xqc_log_t                                       *log;
    xqc_timer_manager_t                             *timer_manager;
    xqc_gp_timer_id_t                               timer_id;
    void                                            *user_data;

    xqc_moq_on_decodable_video_frame_pt             on_decodable_video_frame;
    xqc_moq_request_keyframe_pt                     request_keyframe;
} xqc_moq_av_dejitter_t;

xqc_moq_av_dejitter_t *xqc_moq_av_dejitter_create(
    xqc_bool_t is_video_track, xqc_timer_manager_t *time_manager,
    int audio_sample_rate_hz, void *log, void *media_track);

void xqc_moq_av_dejitter_destroy(xqc_moq_av_dejitter_t *dejitter);

void xqc_moq_av_dejitter_on_video(xqc_moq_av_dejitter_t *dejitter,
    xqc_moq_video_frame_ext_t *frame);

void xqc_moq_av_dejitter_on_audio(xqc_moq_av_dejitter_t *dejitter,
    xqc_moq_audio_frame_ext_t *frame);

uint64_t xqc_moq_av_dejitter_get_largest_video_group_id(
    xqc_moq_av_dejitter_t *dejitter);

#endif /* _XQC_MOQ_TRACK_DEJITTER_H_INCLUDED_ */