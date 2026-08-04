#ifndef _XQC_MOQ_STREAM_H_INCLUDED_
#define _XQC_MOQ_STREAM_H_INCLUDED_

#include "moq/xqc_moq.h"
#include "src/transport/xqc_timer.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/xqc_moq_fec.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_registry.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_update.h"

typedef struct {
    void *(*create)(void *conn, xqc_stream_direction_t dir, void *user_data);
    xqc_stream_t *(*quic_stream)(void *stream);
    ssize_t (*write)(void *stream, uint8_t *send_data, size_t send_data_size, uint8_t fin);
    xqc_int_t (*close)(void *stream);
    xqc_int_t (*cancel)(void *stream, uint64_t err_code);
    xqc_int_t (*stop_sending)(void *stream, uint64_t err_code);
} xqc_moq_trans_stream_ops_t;

typedef void *(*xqc_moq_write_buf_realloc_pt)(void *ptr, size_t size);

#define XQC_MOQ_DATA_STREAM_CANCELLED 0x1

/** defined for uint16_t moq_frame_type in structure xqc_moq_stream_t */
typedef enum {
    MOQ_VIDEO_FRAME,
    MOQ_AUDIO_FRAME
} xqc_moq_frame_type_t;


typedef struct xqc_moq_subgroup_header_s {
    uint64_t                    track_alias;
    uint64_t                    group_id;
    uint64_t                    subgroup_id;
    uint8_t                     subgroup_type;
    uint8_t                     subgroup_priority;
    uint8_t                     subgroup_id_mode;
    uint8_t                     properties_present;
    uint8_t                     default_priority;
    uint8_t                     first_object;
    uint8_t                     end_of_group;
} xqc_moq_subgroup_header_t;


typedef struct xqc_moq_stream_s {
    xqc_moq_session_t           *session;
    uint8_t                     session_lifetime_counted;
    xqc_moq_stream_kind_t       kind;
    void                        *trans_stream; /* Depend on transport type */
    xqc_moq_trans_stream_ops_t  trans_ops;
    union {
        xqc_moq_stream_header_track_msg_t track_header;
        xqc_moq_stream_header_group_msg_t group_header;
    };
    uint8_t                     track_header_valid;

    uint8_t                     *read_buf;
    size_t                      read_buf_cap;
    size_t                      read_buf_len;
    size_t                      read_buf_processed;
    uint8_t                     remain_read_buf[8];
    size_t                      remain_read_buf_len;
    xqc_moq_decode_msg_ctx_t    decode_msg_ctx;
    const xqc_moq_message_codec_entry_t *decode_codec;
    xqc_moq_d18_stream_context_t d18_context;
    xqc_moq_d18_stream_context_t d18_pending_context;
    xqc_moq_d18_message_kind_t  d18_message_kind;
    uint8_t                     d18_context_pending;
    uint8_t                     d18_setup_write_pending;
    uint8_t                     d18_waiting_for_setup;
    uint8_t                     d18_deferred_fin;
    xqc_list_head_t             d18_deferred_list_member;

    uint8_t                     *write_buf;
    size_t                      write_buf_cap;
    size_t                      write_buf_len;
    size_t                      write_buf_processed;
    xqc_moq_write_buf_realloc_pt write_buf_realloc;
    uint8_t                     write_stream_fin;
    uint8_t                     write_fin_submitted;

    uint8_t                     local_request;
    uint8_t                     peer_request;
    uint8_t                     response_received;
    uint8_t                     response_sent;
    uint8_t                     peer_fin_received;
    uint8_t                     request_closed_notified;
    uint8_t                     update_failed_wait_publish_done;
    uint8_t                     d18_goaway_sent;
    uint8_t                     d18_goaway_received;
    uint8_t                     d18_goaway_timer_registered;
    uint8_t                     d18_goaway_timer_fired;
    xqc_moq_msg_type_t          request_type;
    uint64_t                    request_id;
    uint64_t                    d18_goaway_timeout_ms;
    uint64_t                    d18_peer_goaway_timeout_ms;
    xqc_gp_timer_id_t           d18_goaway_timer_id;
    char                        *d18_goaway_uri;
    size_t                      d18_goaway_uri_len;
    xqc_list_head_t             request_list_member;
    xqc_moq_namespace_prefix_t *namespace_subscription;
    xqc_moq_namespace_prefix_t *tracks_subscription;
    uint8_t                     subscribe_tracks_active;
    uint8_t                     subscribe_tracks_forward;
    xqc_list_head_t             d18_local_update_queue;
    xqc_list_head_t             d18_peer_update_queue;
    xqc_moq_message_parameter_t *d18_accepted_params;
    size_t                      d18_accepted_params_num;
    uint8_t                     d18_fetch_type;
    uint8_t                     d18_fetch_group_order;
    uint64_t                    d18_fetch_start_group_id;
    uint64_t                    d18_fetch_start_object_id;
    uint8_t                     d18_fetch_previous_valid;
    uint8_t                     d18_fetch_previous_actual_valid;
    uint64_t                    d18_fetch_previous_group_id;
    uint64_t                    d18_fetch_previous_object_id;
    uint64_t                    d18_fetch_previous_subgroup_id;
    uint8_t                     d18_fetch_previous_priority;
    struct xqc_moq_stream_s     *fetch_data_stream;
    struct xqc_moq_stream_s     *fetch_request_stream;
    uint8_t                     d18_publish_done_pending;
    uint8_t                     d18_publish_done_encoded;
    uint8_t                     d18_publish_done_retrying;
    uint64_t                    d18_publish_done_status;
    uint64_t                    d18_publish_done_stream_count;
    char                        *d18_publish_done_reason;
    size_t                      d18_publish_done_reason_len;

    xqc_moq_track_t             *track;
    xqc_list_head_t             list_member; /* track write_stream_list */
    xqc_list_head_t             recv_list_member; /* track recv_stream_list */
    uint8_t                     recv_stream_counted;
    uint8_t                     recv_stream_processed;
    uint64_t                    group_id;
    uint64_t                    subgroup_id; /* for subgroup stream reuse (sender-side bookkeeping) */
    uint64_t                    object_id;
    uint64_t                    seq_num;
    uint8_t                     cancel_write_close;
    xqc_usec_t                  last_moq_object_write_time;

    xqc_flag_t                  enable_fec;
    float                       fec_code_rate;

    uint16_t                    moq_frame_type;
    xqc_moq_subgroup_header_t   subgroup_header;
    uint8_t                     subgroup_header_valid;
    uint64_t                    subgroup_prev_object_id;
    uint8_t                     subgroup_prev_object_id_valid;
} xqc_moq_stream_t;

xqc_moq_stream_t *xqc_moq_stream_create(xqc_moq_session_t *session);

void xqc_moq_stream_destroy(xqc_moq_stream_t *moq_stream);

xqc_moq_stream_t *xqc_moq_stream_create_with_transport(xqc_moq_session_t *session, xqc_stream_direction_t direction);

xqc_int_t xqc_moq_stream_close(xqc_moq_stream_t *moq_stream);

xqc_int_t xqc_moq_stream_cancel(xqc_moq_stream_t *moq_stream, uint64_t err_code);

xqc_int_t xqc_moq_stream_stop_sending(xqc_moq_stream_t *moq_stream, uint64_t err_code);

xqc_int_t xqc_moq_stream_write(xqc_moq_stream_t *moq_stream);

void xqc_moq_stream_on_track_write(xqc_moq_stream_t *moq_stream, xqc_moq_track_t *track,
    uint64_t group_id, uint64_t object_id, uint64_t seq_num);

void *xqc_moq_stream_get_or_alloc_cur_decode_msg(xqc_moq_stream_t *moq_stream);

xqc_int_t xqc_moq_stream_classify_d18_control_alloc_failure(
    const xqc_moq_stream_t *moq_stream);

void xqc_moq_stream_free_cur_decode_msg(xqc_moq_stream_t *moq_stream);

void xqc_moq_stream_clean_decode_msg_ctx(xqc_moq_stream_t *moq_stream);

xqc_int_t xqc_moq_stream_process(xqc_moq_stream_t *moq_stream, uint8_t *buf, size_t buf_len, uint8_t fin);

xqc_int_t xqc_moq_session_resume_deferred_streams(
    xqc_moq_session_t *session);

xqc_int_t xqc_moq_stream_process_msg(xqc_moq_stream_t *moq_stream, uint8_t stream_fin,
    xqc_int_t *msg_finish, xqc_int_t *wait_more_data);

void xqc_moq_stream_on_request_closed(xqc_moq_stream_t *moq_stream,
    uint64_t error_code);

uint64_t xqc_moq_stream_peer_close_error(
    const xqc_moq_stream_t *moq_stream);

xqc_moq_track_t *xqc_moq_stream_finish_publish_request(
    xqc_moq_stream_t *moq_stream);

void xqc_moq_stream_finish_request(xqc_moq_stream_t *moq_stream,
    uint64_t error_code);

void xqc_moq_stream_unregister_goaway_timer(
    xqc_moq_stream_t *moq_stream);

#endif /* _XQC_MOQ_STREAM_H_INCLUDED_ */
