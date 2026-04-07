#ifndef _XQC_MOQ_MEDIA_TRACK_H_INCLUDED_
#define _XQC_MOQ_MEDIA_TRACK_H_INCLUDED_

#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_utils.h"

typedef struct xqc_moq_av_dejitter_s xqc_moq_av_dejitter_t;

typedef struct {
    xqc_moq_track_t                 track;
    const xqc_moq_media_container_ops_t   *container_ops;
    xqc_list_head_t                 write_stream_list; /* xqc_moq_stream_t */
    uint64_t                        drop_group_id_before;
    uint64_t                        drop_object_id_before;
    xqc_moq_fps_counter_t           fps_counter;
    /* audio/video dejitter module */
    xqc_moq_av_dejitter_t           *dejitter;
} xqc_moq_media_track_t;

extern const struct xqc_moq_track_ops_s xqc_moq_media_track_ops;

#endif /* _XQC_MOQ_MEDIA_TRACK_H_INCLUDED_ */
