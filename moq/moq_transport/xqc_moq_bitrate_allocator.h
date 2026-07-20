#ifndef _XQC_MOQ_BITRATE_ALLOCATOR_H_INCLUDED_
#define _XQC_MOQ_BITRATE_ALLOCATOR_H_INCLUDED_

#include "xquic/xquic_typedef.h"
#include "moq/xqc_moq.h"
#include "moq/moq_transport/xqc_moq_utils.h"

struct xqc_moq_session_s;

#define XQC_MOQ_DELAY_DATA_SIZE 10

typedef struct {
    xqc_int_t       head;
    xqc_int_t       tail;
    xqc_int_t       count;
    xqc_usec_t      epoch_start_ts;
    struct {
        xqc_usec_t  ts;    /* x */
        xqc_usec_t  delay; /* y */
    } delay_point[XQC_MOQ_DELAY_DATA_SIZE];
} xqc_moq_delay_data_set_t;

void xqc_moq_delay_set_insert(xqc_moq_delay_data_set_t *data_set, xqc_usec_t ts, xqc_usec_t delay);

void xqc_moq_delay_set_clear(xqc_moq_delay_data_set_t *data_set);

xqc_int_t xqc_moq_delay_set_is_full(xqc_moq_delay_data_set_t *data_set);

xqc_moq_linear_model_t xqc_moq_delay_set_train(xqc_moq_delay_data_set_t *data_set);

typedef struct xqc_moq_bitrate_allocator_s {
    xqc_moq_delay_data_set_t delay_data_set;
    uint64_t                 target_bitrate;
    uint64_t                 prev_target_bitrate;
    uint64_t                 bitrate_threshold;
    uint64_t                 init_bitrate;
    uint64_t                 max_bitrate;
    uint64_t                 min_bitrate;
    xqc_usec_t               latest_delay;
    xqc_usec_t               last_bitrate_change_time;
    xqc_usec_t               last_bitrate_increase_time;
    xqc_usec_t               last_bitrate_decrease_time;
    xqc_int_t                delay_over_cnt;
    xqc_int_t                delay_under_cnt;
    double                   prev_slope;

    uint64_t                 target_bandwidth;
} xqc_moq_bitrate_allocator_t;

void xqc_moq_init_bitrate(struct xqc_moq_session_s *session);

void xqc_moq_bitrate_alloc_on_frame_acked(struct xqc_moq_session_s *session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, xqc_usec_t delay, xqc_usec_t create_time, xqc_usec_t now,
    uint64_t stream_len, uint64_t seq_num);

#endif /* _XQC_MOQ_BITRATE_ALLOCATOR_H_INCLUDED_ */
