#ifndef _XQC_MOQ_H_INCLUDED_
#define _XQC_MOQ_H_INCLUDED_

#include <xquic/xquic.h>
#include "moq/xqc_moq_fb_report.h"

#ifdef __cplusplus
extern "C" {
#endif

// #define XQC_ALPN_MOQ_QUIC         "moq-quic"
#define XQC_ALPN_MOQ_QUIC         "moq-00"
#define XQC_ALPN_MOQ_QUIC_INTEROP "moq-14" // used for imquic
#define XQC_ALPN_MOQ_WEBTRANSPORT "moq-wt"

typedef enum {
    XQC_MOQ_VIDEO_KEY,
    XQC_MOQ_VIDEO_DELTA,
} xqc_moq_video_frame_type_t;

typedef struct {
    xqc_moq_video_frame_type_t      type;
    uint64_t                        seq_num;
    uint64_t                        timestamp_us;
    uint8_t                         *video_data;
    uint64_t                        video_len;
    /* LOC Header Extensions */
    uint8_t                         *video_config;
    uint64_t                        video_config_len;
    uint64_t                        video_frame_marking;
    uint8_t                         has_video_config;
    uint8_t                         has_video_frame_marking;
    uint8_t                         *bizinfo;
    uint64_t                        bizinfo_len;
    uint8_t                         has_bizinfo;
} xqc_moq_video_frame_t;

typedef struct {
    uint64_t                        seq_num;
    uint64_t                        timestamp_us;
    uint8_t                         *audio_data;
    uint64_t                        audio_len;
    /* LOC Header Extensions */
    uint64_t                        audio_level;
    uint8_t                         has_audio_level;
    uint8_t                         *bizinfo;
    uint64_t                        bizinfo_len;
    uint8_t                         has_bizinfo;
} xqc_moq_audio_frame_t;

typedef enum {
    XQC_MOQ_CONTAINER_LOC,
    XQC_MOQ_CONTAINER_CMAF,
    XQC_MOQ_CONTAINER_NONE,
} xqc_moq_container_t;

typedef enum {
    XQC_MOQ_TRACK_VIDEO,
    XQC_MOQ_TRACK_AUDIO,
    XQC_MOQ_TRACK_CATALOG,
    XQC_MOQ_TRACK_DATACHANNEL,
    XQC_MOQ_TRACK_DELIVERY_FEEDBACK,
} xqc_moq_track_type_t;

typedef enum {
    XQC_MOQ_TRACK_FOR_PUB,
    XQC_MOQ_TRACK_FOR_SUB,
} xqc_moq_track_role_t;

typedef enum {
    XQC_MOQ_OBJ_STATUS_NORMAL           = 0x0,
    XQC_MOQ_OBJ_STATUS_OBJ_NOT_EXIST    = 0x1,
    XQC_MOQ_OBJ_STATUS_GROUP_NOT_EXIST  = 0x2,
    XQC_MOQ_OBJ_STATUS_GROUP_END        = 0x3,
    XQC_MOQ_OBJ_STATUS_TRACK_END        = 0x4,
} xqc_moq_object_status_t;

typedef struct {
    /* Common */
    char                            *codec; /* Required */
    char                            *mime_type; /* Required */
    xqc_int_t                       bitrate; /* Required */
    char                            *lang; /* Optional */
    /* Video */
    xqc_int_t                       framerate; /* Required */
    xqc_int_t                       width; /* Required */
    xqc_int_t                       height; /* Required */
    xqc_int_t                       display_width; /* Optional */
    xqc_int_t                       display_height; /* Optional */
    /* Audio */
    xqc_int_t                       samplerate; /* Required */
    char                            *channel_config; /* Optional */
    xqc_int_t                       bits_per_sample; /* Optional, audio bit depth (bits per sample) */
} xqc_moq_selection_params_t;

typedef struct {
    char                            *track_namespace;
    char                            *track_name;
    xqc_moq_track_type_t            track_type;
    xqc_moq_selection_params_t      selection_params;
} xqc_moq_track_info_t;

typedef enum {
    XQC_MOQ_TRANSPORT_WEBTRANSPORT,
    XQC_MOQ_TRANSPORT_QUIC,
} xqc_moq_transport_type_t;

typedef enum {
    XQC_MOQ_PUBLISHER               = 0x01,
    XQC_MOQ_SUBSCRIBER              = 0x02,
    XQC_MOQ_PUBSUB                  = 0x03,
} xqc_moq_role_t;

typedef enum {
    XQC_MOQ_FILTER_LAST_GROUP       = 0x1,
    XQC_MOQ_FILTER_LAST_OBJECT      = 0x2,
    XQC_MOQ_FILTER_ABSOLUTE_START   = 0x3,
    XQC_MOQ_FILTER_ABSOLUTE_RANGE   = 0x4,
} xqc_moq_filter_type_t;

typedef struct xqc_moq_session_s xqc_moq_session_t;
typedef struct xqc_moq_stream_s xqc_moq_stream_t;
typedef struct xqc_moq_track_s xqc_moq_track_t;
typedef struct xqc_moq_object_s xqc_moq_object_t;
typedef struct xqc_moq_subgroup_object_s xqc_moq_subgroup_object_t;
typedef struct xqc_moq_catalog_s xqc_moq_catalog_t;
typedef struct xqc_moq_subscribe_s xqc_moq_subscribe_t;
typedef struct xqc_moq_subscribe_msg_s xqc_moq_subscribe_msg_t;
typedef struct xqc_moq_subscribe_ok_msg_s xqc_moq_subscribe_ok_msg_t;
typedef struct xqc_moq_subscribe_error_msg_s xqc_moq_subscribe_error_msg_t;
typedef struct xqc_moq_subscribe_update_msg_s xqc_moq_subscribe_update_msg_t;
typedef struct xqc_moq_publish_msg_s xqc_moq_publish_msg_t;
typedef struct xqc_moq_publish_ok_msg_s xqc_moq_publish_ok_msg_t;
typedef struct xqc_moq_publish_error_msg_s xqc_moq_publish_error_msg_t;
typedef struct xqc_moq_announce_msg_s xqc_moq_announce_msg_t;
typedef struct xqc_moq_announce_ok_msg_s xqc_moq_announce_ok_msg_t;
typedef struct xqc_moq_announce_error_msg_s xqc_moq_announce_error_msg_t;
typedef struct xqc_moq_unannounce_msg_s xqc_moq_unannounce_msg_t;
typedef struct xqc_moq_unsubscribe_msg_s xqc_moq_unsubscribe_msg_t;
typedef struct xqc_moq_publish_done_msg_s xqc_moq_publish_done_msg_t;
typedef struct xqc_moq_client_setup_v14_msg_s xqc_moq_client_setup_v14_msg_t;
typedef struct xqc_moq_server_setup_v14_msg_s xqc_moq_server_setup_v14_msg_t;
typedef struct xqc_moq_goaway_msg_s xqc_moq_goaway_msg_t;
typedef struct xqc_moq_client_setup_msg_s xqc_moq_client_setup_msg_t;
typedef struct xqc_moq_server_setup_msg_s xqc_moq_server_setup_msg_t;
typedef struct xqc_moq_stream_header_track_msg_s xqc_moq_stream_header_track_msg_t;
typedef struct xqc_moq_stream_header_group_msg_s xqc_moq_stream_header_group_msg_t;
typedef struct xqc_moq_decode_msg_ctx_s xqc_moq_decode_msg_ctx_t;
typedef struct xqc_moq_user_session_s {
    xqc_moq_session_t               *session;
    uint8_t                         data[0];
} xqc_moq_user_session_t;

#define XQC_MOQ_SUBGROUP_TYPE_WITH_ID       0x15
#define XQC_MOQ_DEFAULT_SUBGROUP_PRIORITY   0x0
#define XQC_MOQ_INVALID_ID                  ((uint64_t)-1)

typedef enum {
    XQC_MOQ_MSG_OBJECT_STREAM       = 0x0,
    XQC_MOQ_MSG_OBJECT_DATAGRAM     = 0x1,
    XQC_MOQ_MSG_SUBSCRIBE_UPDATE    = 0x2,
    XQC_MOQ_MSG_SUBSCRIBE           = 0x3,
    XQC_MOQ_MSG_SUBSCRIBE_OK        = 0x4,
    XQC_MOQ_MSG_SUBSCRIBE_ERROR     = 0x5,
    XQC_MOQ_MSG_ANNOUNCE            = 0x6,
    XQC_MOQ_MSG_ANNOUNCE_OK         = 0x7,
    XQC_MOQ_MSG_ANNOUNCE_ERROR      = 0x8,
    XQC_MOQ_MSG_UNANNOUNCE          = 0x9,
    XQC_MOQ_MSG_UNSUBSCRIBE         = 0xA,
    // XQC_MOQ_MSG_SUBSCRIBE_DONE      = 0xB,
    XQC_MOQ_MSG_PUBLISH_DONE        = 0xB,
    XQC_MOQ_MSG_ANNOUNCE_CANCEL     = 0xC,
    XQC_MOQ_MSG_TRACK_STATUS_REQUEST = 0xD,
    XQC_MOQ_MSG_TRACK_STATUS        = 0xE,
    XQC_MOQ_MSG_GOAWAY              = 0x10,
    XQC_MOQ_MSG_SUBGROUP            = 0x14,
    XQC_MOQ_MSG_CLIENT_SETUP_V14    = 0x20,
    XQC_MOQ_MSG_SERVER_SETUP_V14    = 0x21,
    XQC_MOQ_MSG_CLIENT_SETUP        = 0x40,
    XQC_MOQ_MSG_SERVER_SETUP        = 0x41,
    XQC_MOQ_MSG_STREAM_HEADER_TRACK = 0x50,
    XQC_MOQ_MSG_STREAM_HEADER_GROUP = 0x51,
    XQC_MOQ_MSG_PUBLISH             = 0x1D,
    XQC_MOQ_MSG_PUBLISH_OK          = 0x1E,
    XQC_MOQ_MSG_PUBLISH_ERROR       = 0x1F,
    /* Phony message types */
    XQC_MOQ_MSG_TRACK_STREAM_OBJECT = 0xA0,
    XQC_MOQ_MSG_GROUP_STREAM_OBJECT = 0xA1,
    XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT = 0xA2,
} xqc_moq_msg_type_t;

typedef enum {
    XQC_MOQ_PARAM_ROLE                = 0x00,
    XQC_MOQ_PARAM_PATH                = 0x01,
    XQC_MOQ_PARAM_AUTH                = 0x02,
    XQC_MOQ_PARAM_AUTHORIZATION_TOKEN = 0x03,
    XQC_MOQ_PARAM_EXTDATA             = 0xA0,
    /* draft-moq-delivery-feedback-00 (experimental) */
    XQC_MOQ_PARAM_DELIVERY_FEEDBACK   = 0xA2,
} xqc_moq_param_type_t;

typedef struct {
    uint64_t                    type;
    uint64_t                    length;
    uint8_t                     *value;
    uint8_t                     is_integer;
    uint64_t                    int_value;
} xqc_moq_message_parameter_t;

typedef struct xqc_moq_object_s {
    uint64_t                    subscribe_id;
    uint64_t                    track_alias;
    uint64_t                    group_id;
    uint64_t                    object_id;
    uint64_t                    subgroup_id;
    uint64_t                    object_id_delta;
    uint64_t                    send_order;
    uint64_t                    status;
    /* Optional Object Header Extensions (parsed from SUBGROUP/Object) */
    uint64_t                    ext_params_num;
    xqc_moq_message_parameter_t *ext_params;
    uint8_t                     *payload;
    uint64_t                    payload_len;
    uint8_t                     custom_id_flag;
} xqc_moq_object_t;

typedef struct xqc_moq_msg_base_s {
    xqc_moq_msg_type_t (*type)();
    xqc_int_t (*encode_len)(struct xqc_moq_msg_base_s *msg_base);
    xqc_int_t (*encode)(struct xqc_moq_msg_base_s *msg_base, uint8_t *buf, size_t buf_cap);
    xqc_int_t (*decode)(uint8_t *buf, size_t buf_len, uint8_t stream_fin, struct xqc_moq_decode_msg_ctx_s *msg_ctx,
                        struct xqc_moq_msg_base_s *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);
    void (*on_msg)(struct xqc_moq_session_s *session, struct xqc_moq_stream_s *moq_stream, struct xqc_moq_msg_base_s *msg_base);
} xqc_moq_msg_base_t;

typedef struct xqc_moq_subscribe_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    track_alias;
    uint64_t                    track_namespace_num;
    char                        *track_namespace;
    size_t                      track_namespace_len;
    char                        *track_name;
    size_t                      track_name_len;
    uint8_t                     subscriber_priority;
    uint8_t                     group_order;
    uint8_t                     forward;
    uint64_t                    filter_type;
    uint64_t                    start_group_id;
    uint64_t                    start_object_id;
    uint64_t                    end_group_id;
    uint64_t                    end_object_id;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_subscribe_msg_t;

typedef struct xqc_moq_subscribe_ok_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    track_alias;
    uint64_t                    expire_ms;
    uint8_t                     group_order;
    uint8_t                     content_exist;
    uint64_t                    largest_group_id;
    uint64_t                    largest_object_id;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_subscribe_ok_msg_t;

typedef struct xqc_moq_subscribe_error_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    error_code;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
    uint64_t                    track_alias;
} xqc_moq_subscribe_error_msg_t;

typedef struct xqc_moq_publish_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    track_alias;
    uint64_t                    track_namespace_num;
    char                        *track_namespace;
    size_t                      track_namespace_len;
    char                        *track_name;
    size_t                      track_name_len;
    uint8_t                     group_order;
    uint8_t                     content_exist;
    uint64_t                    largest_group_id;
    uint64_t                    largest_object_id;
    uint8_t                     forward;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_publish_msg_t;

typedef struct xqc_moq_publish_ok_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint8_t                     forward;
    uint8_t                     subscriber_priority;
    uint8_t                     group_order;
    uint64_t                    filter_type;
    uint64_t                    start_group_id;
    uint64_t                    start_object_id;
    uint64_t                    end_group_id;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_publish_ok_msg_t;

typedef struct xqc_moq_publish_error_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    error_code;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
} xqc_moq_publish_error_msg_t;

typedef struct xqc_moq_unsubscribe_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
} xqc_moq_unsubscribe_msg_t;

typedef struct xqc_moq_publish_done_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    status_code;
    uint64_t                    stream_count;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
} xqc_moq_publish_done_msg_t;

typedef enum {
    XQC_MOQ_PUBLISH_ERR_INTERNAL              = 0x0,
    XQC_MOQ_PUBLISH_ERR_SUBSCRIPTION_EXISTS   = 0x3,
    XQC_MOQ_PUBLISH_ERR_TRACK_NOT_FOUND       = 0x4,
} xqc_moq_publish_error_code_t;

typedef struct {
    uint8_t     forward;
    uint8_t     subscriber_priority;
    uint8_t     group_order;
    uint64_t    filter_type;
    uint64_t    start_group_id;
    uint64_t    start_object_id;
    uint64_t    end_group_id;
    uint64_t    end_object_id;
} xqc_moq_publish_selected_params_t;

typedef void (*xqc_moq_on_session_setup_pt)(xqc_moq_user_session_t *user_session, char *extdata,
    const xqc_moq_message_parameter_t *params, uint64_t params_num);

typedef void (*xqc_moq_on_datachannel_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info);

typedef void (*xqc_moq_on_datachannel_msg_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, uint8_t *msg, size_t msg_len);

typedef void (*xqc_moq_on_subscribe_pt)(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg);

typedef void (*xqc_moq_on_unsubscribe_pt)(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track);

typedef void (*xqc_moq_on_request_keyframe_pt)(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track);

typedef void (*xqc_moq_on_subscribe_ok_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, xqc_moq_subscribe_ok_msg_t *subscribe_ok);

typedef void (*xqc_moq_on_subscribe_error_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, xqc_moq_subscribe_error_msg_t *subscribe_error);

typedef void (*xqc_moq_on_publish_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_msg_t *publish_msg);

typedef void (*xqc_moq_on_publish_ok_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_ok_msg_t *publish_ok);

typedef void (*xqc_moq_on_publish_error_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, xqc_moq_publish_error_msg_t *publish_error);

typedef void (*xqc_moq_on_publish_done_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_done_msg_t *publish_done);

typedef void (*xqc_moq_on_publish_accept_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_msg_t *publish_msg, xqc_moq_publish_selected_params_t *params);

typedef void (*xqc_moq_on_catalog_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_info_t **track_info_array,
    xqc_int_t array_size);

typedef void (*xqc_moq_on_video_frame_pt)(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_video_frame_t *video_frame);

typedef void (*xqc_moq_on_audio_frame_pt)(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_audio_frame_t *audio_frame);

/**
 * @brief There are two ways to get the target bitrate. 
 * 1. Call xqc_moq_target_bitrate before encoding. 
 * 2. Register the xqc_moq_on_bitrate_change_pt callback. A callback notification occurs when the target bitrate changes
 * @param track The track whose bitrate changes, NULL if unavailable
 * @param track_info The metadata of the track, NULL if unavailable
 */
typedef void (*xqc_moq_on_bitrate_change_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, uint64_t bitrate);

typedef void (*xqc_moq_on_object_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, xqc_moq_object_t *object);

/* Feedback: media quality (Track-level, from MRR) */
typedef void (*xqc_moq_on_feedback_media_pt)(xqc_moq_user_session_t *user_session,
    const xqc_moq_fb_report_t *report);

/* Feedback: network connection stats (local QUIC layer) */
typedef struct {
    xqc_usec_t  srtt;                   /* smoothed RTT (microseconds) */
    xqc_usec_t  min_rtt;                /* minimum RTT (microseconds) */
    uint64_t    bandwidth_estimate;     /* CC bandwidth estimate (bytes/s) */
    uint64_t    pacing_rate;            /* current pacing rate (bytes/s) */
    uint64_t    inflight_bytes;         /* bytes in flight */
    uint32_t    send_count;             /* total packets sent */
    uint32_t    lost_count;             /* total packets lost */
    uint32_t    recv_count;             /* total packets received */
    double      recent_loss_rate;       /* recent loss rate (sliding window) */
} xqc_moq_fb_network_stats_t;

typedef void (*xqc_moq_on_feedback_network_pt)(xqc_moq_user_session_t *user_session,
    const xqc_moq_fb_network_stats_t *stats);

/* draft-moq-delivery-feedback-00 (experimental): forward declarations */
typedef struct xqc_moq_fb_decision_s xqc_moq_fb_decision_t;
typedef struct xqc_moq_fb_input_s xqc_moq_fb_input_t;
typedef struct xqc_moq_fb_decision_config_s xqc_moq_fb_decision_config_t;

/**
 * Decision callback (Level 2.5).
 * Called after report decode with pre-computed metrics.  Fill out_decision and
 * return XQC_OK to mark the decision as handled (auto-decision will be skipped).
 * If out_decision->action == NONE, this becomes an explicit no-op that suppresses
 * auto fallback.  Return non-OK to fall through to auto-decision (if enabled).
 */
typedef xqc_int_t (*xqc_moq_on_feedback_decision_pt)(xqc_moq_user_session_t *user_session,
    const xqc_moq_fb_report_t *report, const xqc_moq_fb_input_t *input,
    xqc_moq_fb_decision_t *out_decision);

typedef struct {
    xqc_moq_on_session_setup_pt     on_session_setup; /* Required */
    xqc_moq_on_datachannel_pt       on_datachannel; /* Required */
    xqc_moq_on_datachannel_msg_pt   on_datachannel_msg; /* Required */
    /* For Publisher */
    xqc_moq_on_subscribe_pt         on_subscribe; /* Required */
    xqc_moq_on_unsubscribe_pt       on_unsubscribe; /* Optional */
    xqc_moq_on_request_keyframe_pt  on_request_keyframe; /* Required */
    xqc_moq_on_bitrate_change_pt    on_bitrate_change; /* Optional */
    xqc_moq_on_feedback_media_pt    on_feedback_media; /* Optional: Track-level quality from MRR */
    xqc_moq_on_feedback_network_pt  on_feedback_network; /* Optional: connection-level network stats */
    xqc_moq_on_feedback_decision_pt on_feedback_decision; /* Optional: user-driven CC decision */
    /* For Subscriber */
    xqc_moq_on_subscribe_ok_pt      on_subscribe_ok; /* Required */
    xqc_moq_on_subscribe_error_pt   on_subscribe_error; /* Required */
    xqc_moq_on_publish_pt           on_publish; /* Optional */
    xqc_moq_on_publish_ok_pt        on_publish_ok; /* Optional */
    xqc_moq_on_publish_error_pt     on_publish_error; /* Optional */
    xqc_moq_on_publish_done_pt      on_publish_done; /* Optional */
    xqc_moq_on_publish_accept_pt    on_publish_accept; /* Optional */
    xqc_moq_on_catalog_pt           on_catalog; /* Required */
    xqc_moq_on_video_frame_pt       on_video; /* Required */
    xqc_moq_on_audio_frame_pt       on_audio; /* Required */
    xqc_moq_on_object_pt            on_object; /* Optional, raw object callback for CONTAINER_NONE */
} xqc_moq_session_callbacks_t;

XQC_EXPORT_PUBLIC_API
void xqc_moq_init_alpn(xqc_engine_t *engine, xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type);

/**
 * @param extdata The client can send extdata when creating a session. 
 *                This extdata will be received by the server in the on_session_setup callback.
 */
XQC_EXPORT_PUBLIC_API
xqc_moq_session_t *xqc_moq_session_create(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t type, xqc_moq_role_t role, xqc_moq_session_callbacks_t callbacks,
    char *extdata, xqc_int_t enable_client_setup_v14);

/**
 * @brief Create a MOQ session with custom CLIENT_SETUP params.
 * @param setup_params Optional array of parameters to include in CLIENT_SETUP.
 *        If non-NULL and setup_params_num > 0, these replace the default ROLE/PATH/EXTDATA set
 *        and must include XQC_MOQ_PARAM_ROLE themselves.
 * @note  setup_params is only used during this call and is not retained by the library.
 */
XQC_EXPORT_PUBLIC_API
xqc_moq_session_t *xqc_moq_session_create_with_params(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t type, xqc_moq_role_t role, xqc_moq_session_callbacks_t callbacks,
    char *extdata, xqc_int_t enable_client_setup_v14,
    xqc_moq_message_parameter_t *setup_params, uint64_t setup_params_num);

XQC_EXPORT_PUBLIC_API
void xqc_moq_session_destroy(xqc_moq_session_t *session);

/* draft-moq-delivery-feedback-00 (experimental)
 * Three control levels: auto (default), decision callback, or hybrid.
 * See set_auto_cc_feedback / set_feedback_decision_config / on_feedback_decision.
 */

typedef enum {
    XQC_MOQ_FB_ACTION_NONE            = 0,
    XQC_MOQ_FB_ACTION_PACING_GAIN     = 1,
    XQC_MOQ_FB_ACTION_PACING_RATE     = 2,
    XQC_MOQ_FB_ACTION_TARGET_BITRATE  = 3,
} xqc_moq_fb_action_type_t;

typedef struct xqc_moq_fb_decision_s {
    xqc_moq_fb_action_type_t action;
    union {
        struct { float gain; }       pacing_gain;
        struct { uint64_t rate; }    pacing_rate;
        struct { uint64_t bitrate; } target_bitrate;
    } u;
} xqc_moq_fb_decision_t;

typedef struct xqc_moq_fb_input_s {
    double   loss_rate;
    double   late_rate;
    uint64_t playout_ahead_ms;
    uint64_t estimated_bw_kbps;
} xqc_moq_fb_input_t;

typedef struct xqc_moq_fb_decision_config_s {
    uint64_t   playout_critical_ms;
    uint64_t   playout_warning_ms;
    float      playout_critical_gain;
    float      playout_warning_gain;
    double     loss_heavy_threshold;
    double     late_heavy_threshold;
    float      heavy_gain;
    double     loss_mild_threshold;
    double     late_mild_threshold;
    float      mild_gain;
    double     loss_severe_threshold;
    uint64_t   bitrate_floor_kbps;
    xqc_usec_t override_duration_us;

    float      recovery_gain;
} xqc_moq_fb_decision_config_t;

XQC_EXPORT_PUBLIC_API
void xqc_moq_session_report_playout_status(xqc_moq_session_t *session, uint64_t playout_ahead_ms);

/**
 * Enable/disable the built-in auto CC feedback decision.
 * Default: enabled (1).  Set 0 to disable; then only the decision callback
 * (on_feedback_decision) will affect CC.
 */
XQC_EXPORT_PUBLIC_API
void xqc_moq_session_set_auto_cc_feedback(xqc_moq_session_t *session, xqc_int_t enable);

/**
 * Override the default decision thresholds for auto mode.
 * Pass NULL to reset to built-in defaults.
 */
XQC_EXPORT_PUBLIC_API
void xqc_moq_session_set_feedback_decision_config(xqc_moq_session_t *session,
    const xqc_moq_fb_decision_config_t *config);

/**
 * Initialize a decision config with sensible defaults.
 */
XQC_EXPORT_PUBLIC_API
void xqc_moq_fb_decision_config_default(xqc_moq_fb_decision_config_t *config);

/**
 * Configure crosslayer gateway safety bounds.
 * Affects rate-limiting interval and gain clamping for ALL dispatches
 * (both auto and user-driven).
 * @param min_interval_us  Minimum interval between consecutive dispatches (default 50ms).
 * @param min_gain         Minimum pacing_gain clamp (default 0.5).
 * @param max_gain         Maximum pacing_gain clamp (default 2.0).
 * @param min_rate         Minimum pacing_rate floor in bytes/s (default 0).
 */
XQC_EXPORT_PUBLIC_API
void xqc_moq_session_set_crosslayer_bounds(xqc_moq_session_t *session,
    xqc_usec_t min_interval_us, float min_gain, float max_gain, uint64_t min_rate);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_session_get_auto_cc_feedback(xqc_moq_session_t *session);

XQC_EXPORT_PUBLIC_API
void xqc_moq_session_get_feedback_decision_config(xqc_moq_session_t *session,
    xqc_moq_fb_decision_config_t *out_config);

XQC_EXPORT_PUBLIC_API
uint64_t xqc_moq_session_get_cc_dispatch_count(xqc_moq_session_t *session);

XQC_EXPORT_PUBLIC_API
float xqc_moq_session_get_last_dispatched_gain(xqc_moq_session_t *session);

XQC_EXPORT_PUBLIC_API
uint64_t xqc_moq_session_get_last_dispatched_rate(xqc_moq_session_t *session);

XQC_EXPORT_PUBLIC_API
uint64_t xqc_moq_session_get_pacing_rate(xqc_moq_session_t *session);

XQC_EXPORT_PUBLIC_API
uint8_t xqc_moq_session_get_cc_override_active(xqc_moq_session_t *session);

XQC_EXPORT_PUBLIC_API
uint64_t xqc_moq_session_get_feedback_reports_sent(xqc_moq_session_t *session);

/**
 * @brief Set application error code and close the connection
 * @param code in range 0x700 ~ 0x7FF
 */
XQC_EXPORT_PUBLIC_API
void xqc_moq_session_app_error(xqc_moq_session_t *session, uint64_t code);

/**
 * @brief Close the MOQT session with a session termination error code (draft-ietf-moq-transport-14, Section 3.4).
 *        Typical usage: if auth_token validation fails during on_session_setup, close with UNAUTHORIZED (0x2).
 * @param code   MOQT session termination error code (e.g. 0x2 for UNAUTHORIZED).
 * @param reason Optional reason phrase (UTF-8 string, can be NULL).
 */
XQC_EXPORT_PUBLIC_API
void xqc_moq_session_close(xqc_moq_session_t *session, uint64_t code, const char *reason);

/**
 * @brief Get session error code in conn_closing or conn_close_notify
 */
XQC_EXPORT_PUBLIC_API
uint64_t xqc_moq_session_get_error(xqc_moq_session_t *session);

/**
 * @brief Call it after xqc_moq_session_create
 * Configure bitrate in bps
 */
XQC_EXPORT_PUBLIC_API
void xqc_moq_configure_bitrate(xqc_moq_session_t *session, uint64_t init_bitrate, uint64_t max_bitrate, uint64_t min_bitrate);

/**
 * @brief There are two ways to get the target bitrate. 
 * 1. Call xqc_moq_target_bitrate before encoding. 
 * 2. Register the xqc_moq_on_bitrate_change_pt callback. A callback notification occurs when the target bitrate changes
 * @return Encode bitrate in bits per second (bps)
 */
XQC_EXPORT_PUBLIC_API
uint64_t xqc_moq_target_bitrate(xqc_moq_session_t *session);

XQC_EXPORT_PUBLIC_API
xqc_moq_track_t *xqc_moq_track_create(xqc_moq_session_t *session, char *track_namespace, char *track_name,
    xqc_moq_track_type_t track_type, xqc_moq_selection_params_t *params,
    xqc_moq_container_t container, xqc_moq_track_role_t role);

XQC_EXPORT_PUBLIC_API
void xqc_moq_track_set_reuse_subgroup_stream(xqc_moq_track_t *track, xqc_int_t reuse);

XQC_EXPORT_PUBLIC_API
void xqc_moq_track_set_target_latency(xqc_moq_track_t *track, uint64_t target_latency_us);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
    xqc_moq_filter_type_t filter_type, uint64_t start_group_id, uint64_t start_object_id,
    uint64_t end_group_id, uint64_t end_object_id, char *authinfo);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_latest(xqc_moq_session_t *session, const char *track_namespace, const char *track_name);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_publish(xqc_moq_session_t *session, xqc_moq_publish_msg_t *publish_msg);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_create_datachannel(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
    xqc_moq_track_t **track, uint64_t *subscribe_id, xqc_int_t raw_object);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_unsubscribe(xqc_moq_session_t *session, uint64_t subscribe_id);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_request_keyframe(xqc_moq_session_t *session, uint64_t subscribe_id);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_ok(xqc_moq_session_t *session, xqc_moq_subscribe_ok_msg_t *subscribe_ok);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_error(xqc_moq_session_t *session, xqc_moq_subscribe_error_msg_t *subscribe_error);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_publish_ok(xqc_moq_session_t *session, xqc_moq_publish_ok_msg_t *publish_ok);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_publish_error(xqc_moq_session_t *session, xqc_moq_publish_error_msg_t *publish_error);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_publish_done(xqc_moq_session_t *session, xqc_moq_publish_done_msg_t *publish_done);

/*
 * @brief Send a message on the default/system datachannel (session singleton).
 * @note  If reuse_subgroup_stream is enabled on the default datachannel PUB track (via
 *        xqc_moq_track_set_reuse_subgroup_stream in on_datachannel callback), this API will
 *        switch to the subgroup-stream based sender and reuse a single stream.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_datachannel(xqc_moq_session_t *session, uint8_t *msg, size_t msg_len);

/*
 * @brief Send a message on a datachannel track (typically created by xqc_moq_create_datachannel()).
 * @note  If xqc_moq_track_set_reuse_subgroup_stream(track, 1) is enabled, this API will reuse one
 *        unidirectional subgroup stream for multiple objects on the same group_id.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_send_datachannel_msg(xqc_moq_session_t *session, xqc_moq_track_t *track,
    uint8_t *msg, size_t msg_len);

/*
 * @note  If xqc_moq_track_set_reuse_subgroup_stream(track, 1) is enabled on a video PUB track, this
 *        API will reuse a single subgroup stream for all frames in the same group (GOP). A new
 *        stream is created when the group changes (keyframe).
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_video_frame(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_video_frame_t *video_frame);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_audio_frame(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_audio_frame_t *audio_frame);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_build_catalog_param_from_track(xqc_moq_track_t *track,
    xqc_moq_message_parameter_t *param);

XQC_EXPORT_PUBLIC_API
void xqc_moq_free_catalog_param(xqc_moq_message_parameter_t *param);

/*
 * @brief Set the raw object mode for a track.
 * @param set raw object not use xquic-loc container.
 * @param raw_object 1: raw object mode, 0: media container mode.
 */
XQC_EXPORT_PUBLIC_API
void xqc_moq_track_set_raw_object(xqc_moq_track_t *track, xqc_int_t raw_object);

/*
 * @brief Write a raw object on a media track in raw_object mode.
 * @note  The track must have raw_object enabled (xqc_moq_track_set_raw_object),
 *        otherwise this API returns error.
 * @note  If xqc_moq_track_set_reuse_subgroup_stream(track, 1) is enabled, objects with the same
 *        (group_id, subgroup_id) will be appended to the same QUIC stream; a new stream will be
 *        created when group_id or subgroup_id changes.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_raw_object(xqc_moq_session_t *session,
    xqc_moq_track_t *track, xqc_moq_object_t *object);

#ifdef __cplusplus
}
#endif

#endif /* _XQC_MOQ_H_INCLUDED_ */
