#ifndef _XQC_MOQ_H_INCLUDED_
#define _XQC_MOQ_H_INCLUDED_

#include <xquic/xquic.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XQC_ALPN_MOQ_DRAFT_05        "moq-05"
#define XQC_ALPN_MOQ_DRAFT_14        "moq-14"
#define XQC_ALPN_MOQ_DRAFT_18        "moqt-18"
#define XQC_ALPN_MOQ_LEGACY          "moq-quic"

/*
 * moq-05 and moq-14 are private version-selection ALPNs used by this
 * implementation. A peer that only advertises the standards-defined moq-00
 * ALPN will not interoperate with these modes.
 */

/* Source-compatible aliases for the ALPN names used before profiles. */
#define XQC_ALPN_MOQ_QUIC            XQC_ALPN_MOQ_LEGACY
#define XQC_ALPN_MOQ_QUIC_INTEROP    XQC_ALPN_MOQ_DRAFT_14
/* Reserved for future WebTransport support; no profile is registered today. */
#define XQC_ALPN_MOQ_WEBTRANSPORT    "moq-wt"

#define XQC_MOQ_VERSION_5            0xff000005
#define XQC_MOQ_VERSION_14           0xff00000E
#define XQC_MOQ_VERSION_18           0xff000012

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

typedef enum {
    XQC_MOQ_FORWARDING_SUBGROUP     = 0,
    XQC_MOQ_FORWARDING_DATAGRAM     = 1,
    XQC_MOQ_FORWARDING_OBJECT       = 2,
    XQC_MOQ_FORWARDING_TRACK        = 3,
    XQC_MOQ_FORWARDING_GROUP        = 4,
} xqc_moq_forwarding_preference_t;

typedef enum {
    XQC_MOQ_GROUP_ORDER_ASCENDING  = 1,
    XQC_MOQ_GROUP_ORDER_DESCENDING = 2,
} xqc_moq_group_order_t;

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
    size_t                      len;
    unsigned char              *data;
} xqc_moq_track_ns_field_t;

typedef struct {
    xqc_moq_track_ns_field_t        *track_namespace_tuple;
    uint64_t                        track_namespace_num;
    char                            *track_namespace;
    char                            *track_name;
    xqc_moq_track_type_t            track_type;
    xqc_moq_selection_params_t      selection_params;
} xqc_moq_track_info_t;

XQC_EXPORT_PUBLIC_API
char *xqc_moq_namespace_tuple_join(const xqc_moq_track_ns_field_t *tuple, uint64_t num);

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

typedef enum {
    XQC_MOQ_GROUP_FILTER_EXACT      = 0,
    XQC_MOQ_GROUP_FILTER_BEFORE     = 1,
} xqc_moq_group_filter_type_t;

typedef struct {
    xqc_moq_group_filter_type_t      type;
    uint64_t                         group_id;
} xqc_moq_group_filter_t;

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
typedef struct xqc_moq_request_ok_msg_s xqc_moq_request_ok_msg_t;
typedef struct xqc_moq_request_error_msg_s xqc_moq_request_error_msg_t;
typedef struct xqc_moq_request_update_msg_s xqc_moq_request_update_msg_t;
typedef struct xqc_moq_publish_blocked_msg_s xqc_moq_publish_blocked_msg_t;
typedef struct xqc_moq_d18_goaway_msg_s xqc_moq_d18_goaway_msg_t;
typedef struct xqc_moq_fetch_msg_s xqc_moq_fetch_msg_t;
typedef struct xqc_moq_fetch_ok_msg_s xqc_moq_fetch_ok_msg_t;
typedef struct xqc_moq_track_status_msg_s xqc_moq_track_status_msg_t;
typedef struct xqc_moq_fetch_header_msg_s xqc_moq_fetch_header_msg_t;

#define XQC_MOQ_REQUEST_CANCELLED 0x1
#define XQC_MOQ_REQUEST_STREAM_GOING_AWAY 0x4
typedef struct xqc_moq_subscribe_namespace_msg_s xqc_moq_subscribe_namespace_msg_t;
typedef struct xqc_moq_subscribe_tracks_msg_s xqc_moq_subscribe_tracks_msg_t;
typedef struct xqc_moq_subscribe_namespace_ok_msg_s xqc_moq_subscribe_namespace_ok_msg_t;
typedef struct xqc_moq_subscribe_namespace_error_msg_s xqc_moq_subscribe_namespace_error_msg_t;
typedef struct xqc_moq_unsubscribe_namespace_msg_s xqc_moq_unsubscribe_namespace_msg_t;
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
    XQC_MOQ_MSG_REQUEST_ERROR       = 0x5,
    XQC_MOQ_MSG_SUBSCRIBE_ERROR     = XQC_MOQ_MSG_REQUEST_ERROR,
    XQC_MOQ_MSG_PUBLISH_NAMESPACE   = 0x6,
    XQC_MOQ_MSG_REQUEST_OK          = 0x7,
    XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE = 0x9,
    XQC_MOQ_MSG_UNSUBSCRIBE         = 0xA,
    // XQC_MOQ_MSG_SUBSCRIBE_DONE      = 0xB,
    XQC_MOQ_MSG_PUBLISH_DONE        = 0xB,
    XQC_MOQ_MSG_TRACK_STATUS_REQUEST = 0xD,
    XQC_MOQ_MSG_TRACK_STATUS        = 0xE,
    XQC_MOQ_MSG_GOAWAY              = 0x10,
    XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE        = 0x11,
    XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK     = 0x12,
    XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_ERROR  = 0x13,
    XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE      = 0x14,
    XQC_MOQ_MSG_CLIENT_SETUP_V14    = 0x20,
    XQC_MOQ_MSG_SERVER_SETUP_V14    = 0x21,
    XQC_MOQ_MSG_SETUP               = 0x2F00,
    XQC_MOQ_MSG_CLIENT_SETUP        = 0x40,
    XQC_MOQ_MSG_SERVER_SETUP        = 0x41,
    XQC_MOQ_MSG_STREAM_HEADER_TRACK = 0x50,
    XQC_MOQ_MSG_STREAM_HEADER_GROUP = 0x51,
    XQC_MOQ_MSG_PUBLISH             = 0x1D,
    XQC_MOQ_MSG_PUBLISH_OK          = 0x1E,
    XQC_MOQ_MSG_PUBLISH_ERROR       = 0x1F,
    XQC_MOQ_MSG_FETCH               = 0x16,
    XQC_MOQ_MSG_FETCH_OK            = 0x18,
    XQC_MOQ_MSG_SUBSCRIBE_TRACKS    = 0xA4,
} xqc_moq_msg_type_t;

typedef enum {
    XQC_MOQ_PARAM_ROLE                = 0x00,
    XQC_MOQ_PARAM_PATH                = 0x01,
    XQC_MOQ_PARAM_AUTH                = 0x02,
    XQC_MOQ_PARAM_AUTHORIZATION_TOKEN = 0x03,
    XQC_MOQ_PARAM_EXTDATA             = 0xA0,
    XQC_MOQ_PARAM_CATALOG             = 0xA1,
} xqc_moq_param_type_t;

typedef struct {
    uint64_t                    type;
    uint64_t                    length;
    uint8_t                     *value;
    uint8_t                     is_integer;
    uint64_t                    int_value;
} xqc_moq_message_parameter_t;

typedef struct {
    uint64_t                    token_type;
    uint8_t                     *token_value;
    size_t                      token_value_len;
} xqc_moq_resolved_auth_token_t;

typedef struct {
    xqc_moq_resolved_auth_token_t *tokens;
    size_t                      count;
} xqc_moq_request_auth_t;

typedef struct {
    const xqc_moq_message_parameter_t *setup_params;
    uint64_t                           setup_params_num;
} xqc_moq_session_config_t;

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
    /* Publisher Priority from OBJECT_DATAGRAM (draft-14); not related to send_order */
    uint8_t                     publisher_priority_set;
    uint8_t                     publisher_priority;
    /* Draft-18 Object Properties, encoded as Property key/value pairs. */
    uint8_t                     object_properties_present;
    uint8_t                     *object_properties;
    uint64_t                    object_properties_len;
    /* Draft-18 data-stream metadata. */
    uint8_t                     first_of_subgroup;
    uint8_t                     end_of_group;
    uint8_t                     end_of_stream;
    /* Object Forwarding Preference (draft-14 Section 10.2.1): Subgroup or Datagram */
    uint8_t                     forwarding_preference;
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
    xqc_moq_track_ns_field_t    *track_namespace_tuple;
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
    xqc_moq_request_auth_t      request_auth;
    /* Internal receive buffer for fragmented request-stream input. */
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
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
    uint8_t                     *track_properties;
    size_t                      track_properties_len;
    /* Internal receive buffer for fragmented request-stream input. */
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
} xqc_moq_subscribe_ok_msg_t;

typedef struct xqc_moq_subscribe_error_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    error_code;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
    uint64_t                    track_alias;
} xqc_moq_subscribe_error_msg_t;

typedef struct xqc_moq_request_error_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    error_code;
    uint64_t                    retry_interval;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
    uint8_t                     *redirect;
    size_t                      redirect_len;
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
} xqc_moq_request_error_msg_t;

typedef struct xqc_moq_request_update_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    xqc_moq_request_auth_t      request_auth;
    uint8_t                     d18_param_context;
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
    uint64_t                    d18_error_code;
} xqc_moq_request_update_msg_t;

typedef struct xqc_moq_publish_blocked_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    track_namespace_suffix_num;
    xqc_moq_track_ns_field_t    *track_namespace_suffix;
    char                        *track_name;
    size_t                      track_name_len;
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
} xqc_moq_publish_blocked_msg_t;

typedef struct xqc_moq_d18_goaway_msg_s {
    xqc_moq_msg_base_t          msg_base;
    char                        *new_session_uri;
    size_t                      new_session_uri_len;
    uint64_t                    timeout_ms;
    uint64_t                    request_id;
    uint8_t                     has_request_id;
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
} xqc_moq_d18_goaway_msg_t;

typedef enum {
    XQC_MOQ_FETCH_STANDALONE = 0x01,
    XQC_MOQ_FETCH_JOINING_RELATIVE = 0x02,
    XQC_MOQ_FETCH_JOINING_ABSOLUTE = 0x03,
} xqc_moq_fetch_type_t;

typedef struct xqc_moq_fetch_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    xqc_moq_fetch_type_t        fetch_type;
    uint64_t                    track_namespace_num;
    xqc_moq_track_ns_field_t    *track_namespace_tuple;
    char                        *track_name;
    size_t                      track_name_len;
    uint64_t                    start_group_id;
    uint64_t                    start_object_id;
    uint64_t                    end_group_id;
    uint64_t                    end_object_id;
    uint64_t                    joining_request_id;
    uint64_t                    joining_start;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    xqc_moq_request_auth_t      request_auth;
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
} xqc_moq_fetch_msg_t;

typedef struct xqc_moq_fetch_ok_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint8_t                     end_of_track;
    uint64_t                    end_group_id;
    uint64_t                    end_object_id;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    uint8_t                     *track_properties;
    size_t                      track_properties_len;
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
} xqc_moq_fetch_ok_msg_t;

typedef struct xqc_moq_track_status_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    uint64_t                    track_namespace_num;
    xqc_moq_track_ns_field_t    *track_namespace_tuple;
    char                        *track_name;
    size_t                      track_name_len;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    xqc_moq_request_auth_t      request_auth;
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
} xqc_moq_track_status_msg_t;

typedef struct xqc_moq_fetch_header_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    uint8_t                     fin_received;
} xqc_moq_fetch_header_msg_t;

typedef enum {
    XQC_MOQ_REQUEST_ERROR_INTERNAL       = 0x0,
    XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED   = 0x1,
    XQC_MOQ_REQUEST_ERROR_TIMEOUT        = 0x2,
    XQC_MOQ_REQUEST_ERROR_NOT_SUPPORTED  = 0x3,
    XQC_MOQ_REQUEST_ERROR_MALFORMED_AUTH_TOKEN = 0x4,
    XQC_MOQ_REQUEST_ERROR_EXPIRED_AUTH_TOKEN   = 0x5,
    XQC_MOQ_REQUEST_ERROR_GOING_AWAY    = 0x6,
    XQC_MOQ_REQUEST_ERROR_DOES_NOT_EXIST = 0x10,
    XQC_MOQ_REQUEST_ERROR_INVALID_RANGE = 0x11,
    XQC_MOQ_REQUEST_ERROR_DUPLICATE_SUBSCRIPTION = 0x19,
    XQC_MOQ_REQUEST_ERROR_PREFIX_OVERLAP = 0x30,
    XQC_MOQ_REQUEST_ERROR_INVALID_JOINING_REQUEST_ID = 0x32,
    XQC_MOQ_REQUEST_ERROR_UNSUPPORTED_EXTENSION = 0x33,
    XQC_MOQ_REQUEST_ERROR_REDIRECT       = 0x34,
} xqc_moq_request_error_code_t;

typedef enum {
    XQC_MOQ_PUBLISH_DONE_INTERNAL_ERROR = 0x0,
    XQC_MOQ_PUBLISH_DONE_UNAUTHORIZED = 0x1,
    XQC_MOQ_PUBLISH_DONE_TRACK_ENDED = 0x2,
    XQC_MOQ_PUBLISH_DONE_SUBSCRIPTION_ENDED = 0x3,
    XQC_MOQ_PUBLISH_DONE_GOING_AWAY = 0x4,
    XQC_MOQ_PUBLISH_DONE_TOO_FAR_BEHIND = 0x5,
    XQC_MOQ_PUBLISH_DONE_EXPIRED = 0x6,
    XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED = 0x8,
    XQC_MOQ_PUBLISH_DONE_EXCESSIVE_LOAD = 0x9,
    XQC_MOQ_PUBLISH_DONE_MALFORMED_TRACK = 0x12,
} xqc_moq_publish_done_status_t;

#define XQC_MOQ_PUBLISH_DONE_UNKNOWN_STREAM_COUNT \
    ((UINT64_C(1) << 62) - 1)

typedef struct xqc_moq_publish_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    track_alias;
    uint64_t                    track_namespace_num;
    xqc_moq_track_ns_field_t    *track_namespace_tuple;
    char                        *track_name;
    size_t                      track_name_len;
    uint8_t                     group_order;
    uint8_t                     content_exist;
    uint64_t                    largest_group_id;
    uint64_t                    largest_object_id;
    uint8_t                     forward;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    uint8_t                     *track_properties;
    size_t                      track_properties_len;
    xqc_moq_request_auth_t      request_auth;
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
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

typedef struct xqc_moq_publish_namespace_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    uint64_t                    track_namespace_num;
    xqc_moq_track_ns_field_t    *track_namespace_tuple;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    xqc_moq_request_auth_t      request_auth;
    uint8_t                     *payload;
    uint64_t                    payload_len;
} xqc_moq_publish_namespace_msg_t;

typedef struct xqc_moq_request_ok_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    uint8_t                     *track_properties;
    size_t                      track_properties_len;
    uint8_t                     d18_param_context;
    uint8_t                     *payload;
    size_t                      payload_len;
    size_t                      payload_processed;
} xqc_moq_request_ok_msg_t;

typedef struct xqc_moq_publish_namespace_done_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    uint64_t                    track_namespace_num;
    xqc_moq_track_ns_field_t    *track_namespace_tuple;
} xqc_moq_publish_namespace_done_msg_t;

typedef struct xqc_moq_subscribe_namespace_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    uint64_t                    track_namespace_num;
    xqc_moq_track_ns_field_t    *track_namespace_tuple;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    xqc_moq_request_auth_t      request_auth;
    uint8_t                     *payload;
    uint64_t                    payload_len;
} xqc_moq_subscribe_namespace_msg_t;

typedef struct xqc_moq_subscribe_tracks_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    uint64_t                    track_namespace_num;
    xqc_moq_track_ns_field_t    *track_namespace_tuple;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    xqc_moq_request_auth_t      request_auth;
    uint8_t                     *payload;
    uint64_t                    payload_len;
} xqc_moq_subscribe_tracks_msg_t;

typedef struct xqc_moq_subscribe_namespace_ok_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    xqc_moq_track_ns_field_t   *track_namespace_tuple;
    uint64_t                    track_namespace_num;
} xqc_moq_subscribe_namespace_ok_msg_t;

typedef struct xqc_moq_subscribe_namespace_error_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    uint64_t                    error_code;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
    xqc_moq_track_ns_field_t   *track_namespace_tuple;
    uint64_t                    track_namespace_num;
} xqc_moq_subscribe_namespace_error_msg_t;

typedef struct xqc_moq_unsubscribe_namespace_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    track_namespace_num;
    xqc_moq_track_ns_field_t    *track_namespace_tuple;
} xqc_moq_unsubscribe_namespace_msg_t;

typedef enum {
    XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_INTERNAL_ERROR           = 0x0,
    XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_UNAUTHORIZED             = 0x1,
    XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_TIMEOUT                  = 0x2,
    XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_NOT_SUPPORTED            = 0x3,
    XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_PREFIX_UNKNOWN           = 0x4,
    XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_PREFIX_OVERLAP           = 0x5,
    XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_MALFORMED_AUTH_TOKEN     = 0x10,
    XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_EXPIRED_AUTH_TOKEN       = 0x12,
} xqc_moq_subscribe_namespace_error_code_t;

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

typedef struct {
    uint64_t    request_id;
    uint64_t    start_group_id;
    uint64_t    start_object_id;
    uint64_t    end_group_id;
    uint8_t     subscriber_priority;
    uint8_t     forward;
} xqc_moq_subscribe_update_info_t;

typedef void (*xqc_moq_on_session_setup_pt)(xqc_moq_user_session_t *user_session, char *extdata,
    const xqc_moq_message_parameter_t *params, uint64_t params_num);

typedef void (*xqc_moq_on_datachannel_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info);

typedef void (*xqc_moq_on_datachannel_msg_pt)(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, uint8_t *msg, size_t msg_len);

typedef void (*xqc_moq_on_subscribe_pt)(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg);

typedef void (*xqc_moq_on_subscribe_update_pt)(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track, const xqc_moq_subscribe_update_info_t *update);

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

typedef void (*xqc_moq_on_datagram_object_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_track_t *track, xqc_moq_track_info_t *track_info, xqc_moq_object_t *object);

typedef void (*xqc_moq_on_goaway_pt)(xqc_moq_user_session_t *user_session,
    const char *new_session_uri, size_t new_session_uri_len);

typedef enum {
    XQC_MOQ_GOAWAY_SCOPE_CONTROL = 0,
    XQC_MOQ_GOAWAY_SCOPE_REQUEST = 1,
} xqc_moq_goaway_scope_t;

/**
 * The URI view is owned by the session or request stream and remains valid
 * for the duration of the callback. first_unprocessed_request_id is only set
 * for control-scope GOAWAY; target_request_id is only set for request scope.
 */
typedef void (*xqc_moq_on_goaway_draft18_pt)(
    xqc_moq_user_session_t *user_session, xqc_moq_goaway_scope_t scope,
    uint64_t target_request_id, const char *uri, size_t uri_len,
    uint64_t timeout_ms, uint64_t first_unprocessed_request_id);

typedef void (*xqc_moq_on_request_ok_pt)(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_msg_type_t request_type,
    xqc_moq_request_ok_msg_t *msg);

typedef void (*xqc_moq_on_request_error_pt)(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_msg_type_t request_type,
    xqc_moq_request_error_msg_t *msg);

/**
 * The REQUEST_UPDATE view, its parameters, and resolved authorization tokens
 * are stream-owned and remain valid until the corresponding REQUEST_OK,
 * REQUEST_ERROR, or request-stream terminal event. If a response is written
 * synchronously inside this callback, the view remains valid until the
 * callback returns.
 */
typedef void (*xqc_moq_on_request_update_pt)(
    xqc_moq_user_session_t *user_session, uint64_t target_request_id,
    xqc_moq_msg_type_t request_type,
    const xqc_moq_request_update_msg_t *update);

typedef void (*xqc_moq_on_request_cancelled_pt)(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_msg_type_t request_type, uint8_t locally_initiated,
    uint64_t error_code);

/**
 * The reconstructed Full Track Name view is handler-owned and remains valid
 * only for the duration of this callback.
 */
typedef void (*xqc_moq_on_publish_blocked_pt)(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    const xqc_moq_track_ns_field_t *full_namespace,
    uint64_t full_namespace_num, const char *track_name,
    size_t track_name_len);

typedef void (*xqc_moq_on_publish_namespace_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_publish_namespace_msg_t *msg);

typedef void (*xqc_moq_on_publish_namespace_done_pt)(xqc_moq_user_session_t *user_session,
    uint64_t request_id, const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num, uint64_t error_code);

/* Callback namespace tuple storage is valid only for the callback duration. */
typedef void (*xqc_moq_on_namespace_pt)(xqc_moq_user_session_t *user_session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num);

typedef void (*xqc_moq_on_namespace_done_pt)(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num);

typedef void (*xqc_moq_on_subscribe_namespace_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_namespace_msg_t *msg);

typedef void (*xqc_moq_on_subscribe_tracks_pt)(
    xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_tracks_msg_t *msg);

typedef void (*xqc_moq_on_fetch_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_fetch_msg_t *msg);

typedef void (*xqc_moq_on_track_status_pt)(
    xqc_moq_user_session_t *user_session,
    xqc_moq_track_status_msg_t *msg);

typedef void (*xqc_moq_on_fetch_ok_pt)(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_fetch_ok_msg_t *msg);

typedef void (*xqc_moq_on_fetch_header_pt)(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    uint8_t fin);

typedef void (*xqc_moq_on_fetch_object_pt)(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_object_t *object);

typedef void (*xqc_moq_on_fetch_range_pt)(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    uint64_t group_id, uint64_t object_id, uint8_t unknown,
    uint8_t end_of_stream);

typedef void (*xqc_moq_on_track_status_ok_pt)(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_request_ok_msg_t *msg);

typedef void (*xqc_moq_on_subscribe_namespace_ok_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_namespace_ok_msg_t *msg);

typedef void (*xqc_moq_on_subscribe_namespace_error_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_namespace_error_msg_t *msg);

typedef void (*xqc_moq_on_unsubscribe_namespace_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_unsubscribe_namespace_msg_t *msg);

typedef struct {
    xqc_moq_on_session_setup_pt     on_session_setup; /* Required */
    xqc_moq_on_datachannel_pt       on_datachannel; /* Required */
    xqc_moq_on_datachannel_msg_pt   on_datachannel_msg; /* Required */
    /* For Publisher */
    xqc_moq_on_subscribe_pt         on_subscribe; /* Required */
    xqc_moq_on_subscribe_update_pt  on_subscribe_update; /* Optional */
    xqc_moq_on_unsubscribe_pt       on_unsubscribe; /* Optional */
    xqc_moq_on_request_keyframe_pt  on_request_keyframe; /* Required */
    xqc_moq_on_bitrate_change_pt    on_bitrate_change; /* Optional */
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
    xqc_moq_on_datagram_object_pt   on_datagram_object; /* Optional, callback for OBJECT_DATAGRAM */
    xqc_moq_on_goaway_pt            on_goaway; /* Optional, callback for GOAWAY message */
    xqc_moq_on_request_ok_pt        on_request_ok; /* Optional, response on a local request stream */
    xqc_moq_on_request_error_pt     on_request_error; /* Optional, error response on a local request stream */
    xqc_moq_on_publish_namespace_pt on_publish_namespace; /* Optional, incoming namespace advertisement */
    xqc_moq_on_publish_namespace_done_pt on_publish_namespace_done; /* Optional, namespace request ended */
    xqc_moq_on_subscribe_namespace_pt         on_subscribe_namespace; /* Optional, server-side: incoming request */
    xqc_moq_on_subscribe_tracks_pt            on_subscribe_tracks; /* Optional, incoming track discovery request */
    xqc_moq_on_fetch_pt                       on_fetch; /* Optional, incoming FETCH request */
    xqc_moq_on_track_status_pt                on_track_status; /* Optional, incoming TRACK_STATUS request */
    xqc_moq_on_fetch_ok_pt                    on_fetch_ok; /* Optional, FETCH accepted */
    xqc_moq_on_fetch_header_pt                on_fetch_header; /* Optional, FETCH data stream opened */
    xqc_moq_on_fetch_object_pt                on_fetch_object; /* Optional, Object on a FETCH stream */
    xqc_moq_on_fetch_range_pt                 on_fetch_range; /* Optional, FETCH end-of-range record */
    xqc_moq_on_track_status_ok_pt             on_track_status_ok; /* Optional, TRACK_STATUS accepted */
    xqc_moq_on_subscribe_namespace_ok_pt      on_subscribe_namespace_ok; /* Optional, client-side: response */
    xqc_moq_on_subscribe_namespace_error_pt   on_subscribe_namespace_error; /* Optional, client-side: response */
    xqc_moq_on_unsubscribe_namespace_pt       on_unsubscribe_namespace; /* Optional */
    xqc_moq_on_namespace_pt         on_namespace; /* Optional, draft-18 namespace discovered */
    xqc_moq_on_namespace_done_pt    on_namespace_done; /* Optional, draft-18 namespace withdrawn */
} xqc_moq_session_callbacks_t;

typedef enum {
    XQC_MOQ_DRAFT18_AUTH_DELETE = 0x00,
    XQC_MOQ_DRAFT18_AUTH_REGISTER = 0x01,
    XQC_MOQ_DRAFT18_AUTH_USE_ALIAS = 0x02,
    XQC_MOQ_DRAFT18_AUTH_USE_VALUE = 0x03,
} xqc_moq_draft18_auth_alias_type_t;

typedef struct {
    uint64_t                    alias_type;
    uint64_t                    token_alias;
    uint64_t                    token_type;
    const uint8_t               *token_value;
    size_t                      token_value_len;
} xqc_moq_draft18_auth_token_t;

typedef struct {
    const char                  *authority;
    const char                  *path;
    const char                  *implementation;
    const xqc_moq_draft18_auth_token_t *authorization_tokens;
    size_t                      authorization_token_count;
    uint64_t                    max_auth_token_cache_size;
    uint8_t                     has_max_auth_token_cache_size;
} xqc_moq_draft18_setup_config_t;

XQC_EXPORT_PUBLIC_API
void xqc_moq_init_alpn(xqc_engine_t *engine, xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type);

XQC_EXPORT_PUBLIC_API
void xqc_moq_init_alpn_draft18(xqc_engine_t *engine,
    xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type);

/**
 * The MoQ version and message format are selected exclusively by the
 * negotiated ALPN.
 *
 * @param extdata The client can send extdata when creating a session.
 *                This extdata will be received by the server in the on_session_setup callback.
 */
XQC_EXPORT_PUBLIC_API
xqc_moq_session_t *xqc_moq_session_create(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t type, xqc_moq_role_t role, xqc_moq_session_callbacks_t callbacks,
    char *extdata);

/**
 * Create a MoQ session using the version profile selected by negotiated ALPN.
 *
 * The immutable version profile is derived directly from negotiated ALPN.
 */
XQC_EXPORT_PUBLIC_API
xqc_moq_session_t *xqc_moq_session_create_ex(void *conn,
    xqc_moq_user_session_t *user_session, xqc_moq_transport_type_t type,
    xqc_moq_role_t role, xqc_moq_session_callbacks_t callbacks,
    const xqc_moq_session_config_t *config);

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
    char *extdata, xqc_moq_message_parameter_t *setup_params,
    uint64_t setup_params_num);

XQC_EXPORT_PUBLIC_API
xqc_moq_session_t *xqc_moq_session_create_draft18(void *conn,
    xqc_moq_user_session_t *user_session, xqc_moq_transport_type_t type,
    xqc_moq_role_t role, xqc_moq_session_callbacks_t callbacks,
    const char *authority, const char *path);

XQC_EXPORT_PUBLIC_API
xqc_moq_session_t *xqc_moq_session_create_draft18_with_config(
    void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t type, xqc_moq_role_t role,
    xqc_moq_session_callbacks_t callbacks,
    const xqc_moq_draft18_setup_config_t *config);

XQC_EXPORT_PUBLIC_API
size_t xqc_moq_session_get_peer_setup_auth_token_count(
    const xqc_moq_session_t *session);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_session_get_peer_setup_auth_token(
    const xqc_moq_session_t *session, size_t index, uint64_t *token_type,
    const uint8_t **token_value, size_t *token_value_len);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_session_mark_peer_auth_token_expired(
    xqc_moq_session_t *session, uint64_t token_alias);

XQC_EXPORT_PUBLIC_API
void xqc_moq_session_destroy(xqc_moq_session_t *session);

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

XQC_EXPORT_PUBLIC_API
void xqc_moq_session_set_enable_datachannel(xqc_moq_session_t *session, xqc_int_t enable);

XQC_EXPORT_PUBLIC_API
void xqc_moq_session_set_enable_catalog(xqc_moq_session_t *session, xqc_int_t enable);

/**
 * @brief Set the optional callback for abrupt draft-18 request-stream
 *        termination without changing the legacy callbacks structure ABI.
 */
XQC_EXPORT_PUBLIC_API
void xqc_moq_session_set_request_cancelled_callback(
    xqc_moq_session_t *session,
    xqc_moq_on_request_cancelled_pt callback);

/* Additive setter: keeps xqc_moq_session_callbacks_t ABI unchanged. */
XQC_EXPORT_PUBLIC_API
void xqc_moq_session_set_request_update_callback(
    xqc_moq_session_t *session,
    xqc_moq_on_request_update_pt callback);

/* Additive setter: keeps xqc_moq_session_callbacks_t ABI unchanged. */
XQC_EXPORT_PUBLIC_API
void xqc_moq_session_set_publish_blocked_callback(
    xqc_moq_session_t *session,
    xqc_moq_on_publish_blocked_pt callback);

/* Additive setter: keeps xqc_moq_session_callbacks_t ABI unchanged. */
XQC_EXPORT_PUBLIC_API
void xqc_moq_session_set_goaway_draft18_callback(
    xqc_moq_session_t *session,
    xqc_moq_on_goaway_draft18_pt callback);

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
xqc_moq_track_t *xqc_moq_track_create_with_ns_tuple(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *ns_tuple, uint64_t ns_num,
    char *track_name, xqc_moq_track_type_t track_type,
    xqc_moq_selection_params_t *params, xqc_moq_container_t container,
    xqc_moq_track_role_t role);

XQC_EXPORT_PUBLIC_API
void xqc_moq_track_set_reuse_subgroup_stream(xqc_moq_track_t *track, xqc_int_t reuse);

/*
 * @brief Stop receiving currently open data streams that match a group filter.
 * @note  This sends receiver-side STOP_SENDING only. It does not send RESET_STREAM
 *        and does not update the subscription window by itself.
 * @note  XQC_MOQ_GROUP_FILTER_BEFORE matches streams with group_id < filter->group_id.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_track_cancel_recv(xqc_moq_track_t *track, const xqc_moq_group_filter_t *filter);

/*
 * @brief Stop sending currently open data streams that match a group filter.
 * @note  This sends sender-side RESET_STREAM for matched streams.
 * @note  XQC_MOQ_GROUP_FILTER_BEFORE also drops future writes before filter->group_id.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_track_cancel_write(xqc_moq_track_t *track, const xqc_moq_group_filter_t *filter);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
    xqc_moq_filter_type_t filter_type, uint64_t start_group_id, uint64_t start_object_id,
    uint64_t end_group_id, uint64_t end_object_id, char *authinfo);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_with_ns_tuple(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *ns_tuple, uint64_t ns_num,
    const char *track_name, xqc_moq_filter_type_t filter_type,
    uint64_t start_group_id, uint64_t start_object_id,
    uint64_t end_group_id, uint64_t end_object_id, char *authinfo);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_latest(xqc_moq_session_t *session, const char *track_namespace, const char *track_name);

/*
 * @brief Send SUBSCRIBE_UPDATE for an existing local subscription.
 * @note  This only advances/narrows the subscription window on the control stream.
 *        It does not cancel already-open data streams; use xqc_moq_track_cancel_recv
 *        when immediate receiver-side cancellation is also needed.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_update(xqc_moq_session_t *session, uint64_t subscribe_id,
    uint64_t start_group_id, uint64_t start_object_id, uint64_t end_group_id);

/*
 * Advertise a namespace and notify active matching SUBSCRIBE_NAMESPACE
 * prefixes. Draft-18 sends NAMESPACE on each accepted request stream;
 * draft-14 keeps the legacy PUBLISH_NAMESPACE control-stream path.
 * Applications should call this before publishing tracks in that namespace;
 * xqc_moq_publish() does not implicitly advertise the namespace.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_publish_namespace(xqc_moq_session_t *session,
    xqc_moq_publish_namespace_msg_t *publish_namespace);

/*
 * Cancel a draft-18 request stream by Request ID. Both open stream directions
 * are abruptly terminated with the MOQT CANCELLED (0x1) stream error code.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_cancel_request(xqc_moq_session_t *session, uint64_t request_id);

/*
 * End an advertised namespace and notify active matching
 * SUBSCRIBE_NAMESPACE prefixes. Draft-18 sends NAMESPACE_DONE on each
 * accepted request stream; draft-14 keeps the legacy
 * PUBLISH_NAMESPACE_DONE control-stream path. The call fails while an
 * exact-match namespace publish is still active.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_publish_namespace_done(xqc_moq_session_t *session,
    xqc_moq_publish_namespace_done_msg_t *publish_namespace_done);

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

/*
 * Send a draft-18 REQUEST_OK on the peer-initiated request stream identified
 * by request_id. A request stream can receive exactly one response.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_request_ok(xqc_moq_session_t *session,
    uint64_t request_id, xqc_moq_request_ok_msg_t *request_ok);

/*
 * Send a draft-18 REQUEST_ERROR on the peer-initiated request stream
 * identified by request_id. A request stream can receive exactly one response.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_request_error(xqc_moq_session_t *session,
    uint64_t request_id, xqc_moq_request_error_msg_t *request_error);

/*
 * Send a draft-18 REQUEST_UPDATE on an established request stream.
 * target_request_id identifies the initial request.  request_id is allocated
 * from the session-wide Request ID space when update->request_id is zero.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_request_update(xqc_moq_session_t *session,
    uint64_t target_request_id, xqc_moq_request_update_msg_t *update);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_publish_ok(xqc_moq_session_t *session, xqc_moq_publish_ok_msg_t *publish_ok);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_publish_error(xqc_moq_session_t *session, xqc_moq_publish_error_msg_t *publish_error);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_publish_done(xqc_moq_session_t *session, xqc_moq_publish_done_msg_t *publish_done);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_namespace(xqc_moq_session_t *session,
    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace);

/*
 * Subscribe to all current and future tracks whose namespace matches the
 * supplied draft-18 prefix. The request is sent on a new bidirectional
 * request stream; request_id is allocated when the field is zero.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_tracks(xqc_moq_session_t *session,
    xqc_moq_subscribe_tracks_msg_t *subscribe_tracks);

/*
 * Notify an established peer SUBSCRIBE_TRACKS request that a matching Full
 * Track Name is currently blocked. The wire namespace is shortened relative
 * to that request stream's accepted prefix.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_publish_blocked(
    xqc_moq_session_t *session, uint64_t subscribe_tracks_request_id,
    const xqc_moq_track_ns_field_t *full_namespace,
    uint64_t full_namespace_num, const char *track_name,
    size_t track_name_len);

/*
 * Send a namespace acceptance response. Draft-18 sessions use REQUEST_OK on
 * the peer request stream; legacy sessions retain SUBSCRIBE_NAMESPACE_OK on
 * the control stream.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_namespace_ok(xqc_moq_session_t *session,
    xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok);

/*
 * Send a namespace rejection response. Draft-18 sessions use REQUEST_ERROR
 * and draft-18 request error codes on the peer request stream; legacy
 * sessions retain SUBSCRIBE_NAMESPACE_ERROR on the control stream.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_namespace_error(xqc_moq_session_t *session,
    xqc_moq_subscribe_namespace_error_msg_t *subscribe_namespace_error);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_unsubscribe_namespace(xqc_moq_session_t *session,
    xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace);

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

#define XQC_MOQ_CATALOG_PARAM_NOT_FOUND    1
#define XQC_MOQ_CATALOG_PARAM_DECODE_ERR   2
#define XQC_MOQ_CATALOG_PARAM_NO_MATCH     3

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_apply_catalog_param_to_track(xqc_moq_track_t *track,
    xqc_moq_message_parameter_t *params, uint64_t params_num);

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

/*
 * @brief Send a single MOQT OBJECT_DATAGRAM (draft-ietf-moq-transport-14, Section 10.3.1) on QUIC DATAGRAM.
 * @note  The connection must negotiate max_datagram_frame_size > 0 to actually send datagrams.
 * @note  Publisher priority is read from object->publisher_priority.
 *        End-of-group is inferred from object->status == XQC_MOQ_OBJ_STATUS_GROUP_END.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_send_object_datagram(xqc_moq_session_t *session, xqc_moq_object_t *object);

/** Append one Draft-18 Object to an established FETCH data stream. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_fetch_object(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_object_t *object, uint8_t fin);

/** Append a Draft-18 End of Non-Existent/Unknown Range record. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_fetch_range_end(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, uint64_t group_id, uint64_t object_id,
    uint8_t unknown, uint8_t fin);

/**
 * @brief Send a GOAWAY message to the peer (draft-ietf-moq-transport-14, Section 9.4).
 *        Signals the intent to close the session soon. Can only be sent once per session.
 * @param session  The MOQ session.
 * @param new_session_uri  Optional new session URI (server only, NULL or empty for client).
 * @param uri_len  Length of new_session_uri (0 if not provided).
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_send_goaway(xqc_moq_session_t *session, const char *new_session_uri, size_t uri_len);

/** Send draft-18 GOAWAY on the control stream. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_send_session_goaway_draft18(
    xqc_moq_session_t *session, const char *uri, size_t uri_len,
    uint64_t timeout_ms, uint64_t first_unprocessed_request_id);

/** Send draft-18 GOAWAY on an established request stream. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_send_request_goaway_draft18(
    xqc_moq_session_t *session, uint64_t target_request_id,
    const char *uri, size_t uri_len, uint64_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* _XQC_MOQ_H_INCLUDED_ */
