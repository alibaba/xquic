#ifndef _XQC_MOQ_H_INCLUDED_
#define _XQC_MOQ_H_INCLUDED_

#include <xquic/xquic.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XQC_ALPN_MOQ_QUIC         "moq-quic"
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
} xqc_moq_video_frame_t;

typedef struct {
    uint64_t                        seq_num;
    uint64_t                        timestamp_us;
    uint8_t                         *audio_data;
    uint64_t                        audio_len;
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
} xqc_moq_track_type_t;

typedef enum {
    XQC_MOQ_TRACK_FOR_PUB,
    XQC_MOQ_TRACK_FOR_SUB,
} xqc_moq_track_role_t;

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
typedef struct xqc_moq_catalog_s xqc_moq_catalog_t;
typedef struct xqc_moq_subscribe_s xqc_moq_subscribe_t;
typedef struct xqc_moq_subscribe_msg_s xqc_moq_subscribe_msg_t;
typedef struct xqc_moq_subscribe_ok_msg_s xqc_moq_subscribe_ok_msg_t;
typedef struct xqc_moq_subscribe_error_msg_s xqc_moq_subscribe_error_msg_t;
typedef struct xqc_moq_subscribe_update_msg_s xqc_moq_subscribe_update_msg_t;
typedef struct xqc_moq_announce_msg_s xqc_moq_announce_msg_t;
typedef struct xqc_moq_announce_ok_msg_s xqc_moq_announce_ok_msg_t;
typedef struct xqc_moq_announce_error_msg_s xqc_moq_announce_error_msg_t;
typedef struct xqc_moq_unannounce_msg_s xqc_moq_unannounce_msg_t;
typedef struct xqc_moq_unsubscribe_msg_s xqc_moq_unsubscribe_msg_t;
typedef struct xqc_moq_subscribe_done_msg_s xqc_moq_subscribe_done_msg_t;
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
    XQC_MOQ_MSG_SUBSCRIBE_DONE      = 0xB,
    XQC_MOQ_MSG_ANNOUNCE_CANCEL     = 0xC,
    XQC_MOQ_MSG_TRACK_STATUS_REQUEST = 0xD,
    XQC_MOQ_MSG_TRACK_STATUS        = 0xE,
    XQC_MOQ_MSG_GOAWAY              = 0x10,
    XQC_MOQ_MSG_CLIENT_SETUP        = 0x40,
    XQC_MOQ_MSG_SERVER_SETUP        = 0x41,
    XQC_MOQ_MSG_STREAM_HEADER_TRACK = 0x50,
    XQC_MOQ_MSG_STREAM_HEADER_GROUP = 0x51,
    /* Phony message types */
    XQC_MOQ_MSG_TRACK_STREAM_OBJECT = 0xA0,
    XQC_MOQ_MSG_GROUP_STREAM_OBJECT = 0xA1,
} xqc_moq_msg_type_t;

typedef struct {
    uint64_t                    type;
    uint64_t                    length;
    uint8_t                     *value;
} xqc_moq_message_parameter_t;

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
    char                        *track_namespace;
    size_t                      track_namespace_len;
    char                        *track_name;
    size_t                      track_name_len;
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
    uint64_t                    expire_ms;
    uint64_t                    content_exist;
    uint64_t                    largest_group_id;
    uint64_t                    largest_object_id;
} xqc_moq_subscribe_ok_msg_t;

typedef struct xqc_moq_subscribe_error_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    error_code;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
    uint64_t                    track_alias;
} xqc_moq_subscribe_error_msg_t;

typedef struct xqc_moq_unsubscribe_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
} xqc_moq_unsubscribe_msg_t;

typedef void (*xqc_moq_on_session_setup_pt)(xqc_moq_user_session_t *user_session, char *extdata);

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
 */
typedef void (*xqc_moq_on_bitrate_change_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, uint64_t bitrate);

typedef struct {
    xqc_moq_on_session_setup_pt     on_session_setup; /* Required */
    xqc_moq_on_datachannel_pt       on_datachannel; /* Required */
    xqc_moq_on_datachannel_msg_pt   on_datachannel_msg; /* Required */
    /* For Publisher */
    xqc_moq_on_subscribe_pt         on_subscribe; /* Required */
    xqc_moq_on_unsubscribe_pt       on_unsubscribe; /* Optional */
    xqc_moq_on_request_keyframe_pt  on_request_keyframe; /* Required */
    xqc_moq_on_bitrate_change_pt    on_bitrate_change; /* Optional */
    /* For Subscriber */
    xqc_moq_on_subscribe_ok_pt      on_subscribe_ok; /* Required */
    xqc_moq_on_subscribe_error_pt   on_subscribe_error; /* Required */
    xqc_moq_on_catalog_pt           on_catalog; /* Required */
    xqc_moq_on_video_frame_pt       on_video; /* Required */
    xqc_moq_on_audio_frame_pt       on_audio; /* Required */
} xqc_moq_session_callbacks_t;

XQC_EXPORT_PUBLIC_API
void xqc_moq_init_alpn(xqc_engine_t *engine, xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type);

/**
 * @param extdata The client can send extdata when creating a session. 
 *                This extdata will be received by the server in the on_session_setup callback.
 */
XQC_EXPORT_PUBLIC_API
xqc_moq_session_t *xqc_moq_session_create(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t type, xqc_moq_role_t role, xqc_moq_session_callbacks_t, char *extdata);

XQC_EXPORT_PUBLIC_API
void xqc_moq_session_destroy(xqc_moq_session_t *session);

/**
 * @brief Set application error code and close the connection
 * @param code in range 0x700 ~ 0x7FF
 */
XQC_EXPORT_PUBLIC_API
void xqc_moq_session_app_error(xqc_moq_session_t *session, uint64_t code);

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
    xqc_moq_track_type_t track_type, xqc_moq_selection_params_t *params, xqc_moq_container_t container, xqc_moq_track_role_t role);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
    xqc_moq_filter_type_t filter_type, uint64_t start_group_id, uint64_t start_object_id,
    uint64_t end_group_id, uint64_t end_object_id, char *authinfo);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_latest(xqc_moq_session_t *session, const char *track_namespace, const char *track_name);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_unsubscribe(xqc_moq_session_t *session, uint64_t subscribe_id);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_request_keyframe(xqc_moq_session_t *session, uint64_t subscribe_id);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_ok(xqc_moq_session_t *session, xqc_moq_subscribe_ok_msg_t *subscribe_ok);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_error(xqc_moq_session_t *session, xqc_moq_subscribe_error_msg_t *subscribe_error);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_datachannel(xqc_moq_session_t *session, uint8_t *msg, size_t msg_len);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_video_frame(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_video_frame_t *video_frame);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_audio_frame(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_audio_frame_t *audio_frame);

#ifdef __cplusplus
}
#endif

#endif /* _XQC_MOQ_H_INCLUDED_ */
