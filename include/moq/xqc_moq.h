#ifndef _XQC_MOQ_H_INCLUDED_
#define _XQC_MOQ_H_INCLUDED_

#include <xquic/xquic.h>

#ifdef __cplusplus
extern "C" {
#endif

// #define XQC_ALPN_MOQ_QUIC                   "moq-00"
#define XQC_ALPN_MOQ_QUIC_INTEROP           "moq-00"
#define XQC_ALPN_MOQ_QUIC_V11               "moq-11"
// #define XQC_ALPN_MOQ_QUIC_V05               "moq-quic"
#define XQC_ALPN_MOQ_QUIC_V05               "moq-00"
#define XQC_ALPN_MOQ_WEBTRANSPORT           "moq-wt"
#define XQC_ALPN_MOQ_QUIC_V14               "moq-14"
#define XQC_ALPN_MOQ_CUR_VERSION            XQC_ALPN_MOQ_QUIC_V14

#ifndef XQC_MOQ_INVALID_ALIAS
#define XQC_MOQ_INVALID_ALIAS ((uint64_t)~0ULL)
#endif
#ifndef XQC_MOQ_INVALID_ID
#define XQC_MOQ_INVALID_ID ((uint64_t)~0ULL)
#endif

// Fixed Track_alias to alternative hardcoded values, to keep fast subscribe
#ifndef XQC_MOQ_ALIAS_DATACHANNEL
#define XQC_MOQ_ALIAS_DATACHANNEL ((uint64_t)0)
#endif
#ifndef XQC_MOQ_ALIAS_CATALOG
#define XQC_MOQ_ALIAS_CATALOG ((uint64_t)1)
#endif
#ifndef XQC_MOQ_ALIAS_VIDEO
#define XQC_MOQ_ALIAS_VIDEO ((uint64_t)2)
#endif
#ifndef XQC_MOQ_ALIAS_AUDIO
#define XQC_MOQ_ALIAS_AUDIO ((uint64_t)3)
#endif

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
    XQC_MOQ_TRACK_DEFAULT,
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
    /* New filter type names in draft-12 */
    XQC_MOQ_FILTER_NEXT_GROUP_START     = 0x1,  /* Next Group Start - v11 */
    XQC_MOQ_FILTER_LARGEST_OBJECT       = 0x2,  /* Largest Object - v11 */
    XQC_MOQ_FILTER_ABSOLUTE_START       = 0x3,  /* AbsoluteStart */
    XQC_MOQ_FILTER_ABSOLUTE_RANGE       = 0x4,  /* AbsoluteRange */
    
    /* draft-10 and before, keep backward compatibility */
    XQC_MOQ_FILTER_LAST_GROUP           = 0x1,  /* deprecated, use XQC_MOQ_FILTER_NEXT_GROUP_START */
    XQC_MOQ_FILTER_LAST_OBJECT          = 0x2,  /* deprecated, use XQC_MOQ_FILTER_LARGEST_OBJECT */
} xqc_moq_filter_type_t;

/* 前向声明所需的类型 */
typedef struct xqc_moq_session_s xqc_moq_session_t;
typedef struct xqc_moq_stream_s xqc_moq_stream_t;
typedef struct xqc_moq_track_s xqc_moq_track_t;
typedef struct xqc_moq_object_s xqc_moq_object_t;
typedef struct xqc_moq_catalog_s xqc_moq_catalog_t;
typedef struct xqc_moq_subscribe_s xqc_moq_subscribe_t;
typedef struct xqc_moq_unsubscribe_s xqc_moq_unsubscribe_t;
typedef struct xqc_moq_subscribe_msg_v05_s xqc_moq_subscribe_msg_t_v05;
typedef struct xqc_moq_subscribe_msg_v13_s xqc_moq_subscribe_msg_t_v13;
typedef struct xqc_moq_publish_msg_s xqc_moq_publish_msg_t;
typedef struct xqc_moq_publish_ok_msg_s xqc_moq_publish_ok_msg_t;
typedef struct xqc_moq_publish_error_msg_s xqc_moq_publish_error_msg_t;
typedef struct xqc_moq_subscribe_ok_msg_s xqc_moq_subscribe_ok_msg_t;
typedef struct xqc_moq_subscribe_error_msg_s xqc_moq_subscribe_error_msg_t;
typedef struct xqc_moq_subscribe_update_msg_s_v05 xqc_moq_subscribe_update_msg_t_v05;
typedef struct xqc_moq_subscribe_update_msg_s_v13 xqc_moq_subscribe_update_msg_t_v13;
typedef struct xqc_moq_fetch_msg_s xqc_moq_fetch_msg_t;
typedef struct xqc_moq_announce_msg_s xqc_moq_announce_msg_t;
typedef struct xqc_moq_announce_ok_msg_s xqc_moq_announce_ok_msg_t;
typedef struct xqc_moq_announce_error_msg_s xqc_moq_announce_error_msg_t;
typedef struct xqc_moq_unannounce_msg_s xqc_moq_unannounce_msg_t;
typedef struct xqc_moq_unsubscribe_msg_s xqc_moq_unsubscribe_msg_t;
typedef struct xqc_moq_subscribe_done_msg_s xqc_moq_subscribe_done_msg_t;
typedef struct xqc_moq_object_datagram_s xqc_moq_object_datagram_t;
typedef struct xqc_moq_goaway_msg_s xqc_moq_goaway_msg_t;
typedef struct xqc_moq_client_setup_msg_s xqc_moq_client_setup_msg_t;
typedef struct xqc_moq_server_setup_msg_s xqc_moq_server_setup_msg_t;
typedef struct xqc_moq_stream_header_track_msg_s xqc_moq_stream_header_track_msg_t;
typedef struct xqc_moq_stream_header_group_msg_s xqc_moq_stream_header_group_msg_t;
typedef struct xqc_moq_stream_header_subgroup_msg_s xqc_moq_stream_header_subgroup_msg_t;
typedef struct xqc_moq_decode_msg_ctx_s xqc_moq_decode_msg_ctx_t;
typedef struct xqc_moq_track_status_msg_s xqc_moq_track_status_msg_t;
typedef struct xqc_moq_track_status_ok_msg_s xqc_moq_track_status_ok_msg_t;
typedef struct xqc_moq_track_status_error_msg_s xqc_moq_track_status_error_msg_t;
typedef struct xqc_moq_max_request_id_msg_s xqc_moq_max_request_id_msg_t;
typedef struct xqc_moq_subscribe_namespace_msg_s xqc_moq_subscribe_namespace_msg_t;
typedef struct xqc_moq_subscribe_namespace_ok_msg_s xqc_moq_subscribe_namespace_ok_msg_t;
typedef struct xqc_moq_unsubscribe_namespace_msg_s xqc_moq_unsubscribe_namespace_msg_t;

typedef struct xqc_moq_msg_track_namespace_s {
    uint64_t                    track_namespace_num;
    uint64_t                    *track_namespace_len;
    char                        **track_namespace;
} xqc_moq_msg_track_namespace_t;
typedef struct xqc_moq_user_session_s {
    xqc_moq_session_t               *session;
    uint32_t                        version_num;
    uint8_t                         data[0];
} xqc_moq_user_session_t;

typedef enum {
    XQC_MOQ_STATUS_INTERNAL_ERROR       = 0x00,
    XQC_MOQ_STATUS_UNAUTHORIZED         = 0x01,
    XQC_MOQ_STATUS_TRACK_ENDED          = 0x02,
    XQC_MOQ_STATUS_SUBSCRIPTION_ENDED   = 0x03,
    XQC_MOQ_STATUS_GOING_AWAY           = 0x04,
    XQC_MOQ_STATUS_EXPIRED              = 0x05,
    XQC_MOQ_STATUS_TOO_FAR_BEHIND       = 0x06,
} xqc_moq_subscribe_done_status_t;

typedef enum {
    XQC_MOQ_OBJ_STATUS_NORMAL           = 0x0,
    XQC_MOQ_OBJ_STATUS_OBJ_NOT_EXIST    = 0x1,
    XQC_MOQ_OBJ_STATUS_GROUP_NOT_EXIST  = 0x2,
    XQC_MOQ_OBJ_STATUS_GROUP_END        = 0x3,
    XQC_MOQ_OBJ_STATUS_TRACK_END        = 0x4,
} xqc_moq_object_status_t;

typedef enum {
    XQC_MOQ_MSG_OBJECT_STREAM       = 0x0,
    XQC_MOQ_MSG_OBJECT_DATAGRAM     = 0x1,
    XQC_MOQ_MSG_SUBSCRIBE_UPDATE    = 0x2,
    XQC_MOQ_MSG_SUBSCRIBE           = 0x3,
    XQC_MOQ_MSG_SUBSCRIBE_OK        = 0x4,
    XQC_MOQ_MSG_SUBSCRIBE_ERROR     = 0x5,
    XQC_MOQ_MSG_ANNOUNCE            = 0x6,  /* Alias for PUBLISH_NAMESPACE */
    XQC_MOQ_MSG_PUBLISH_NAMESPACE   = 0x6,   /* Per draft-ietf-moq-transport */
    XQC_MOQ_MSG_ANNOUNCE_OK         = 0x7,
    XQC_MOQ_MSG_ANNOUNCE_ERROR      = 0x8,
    XQC_MOQ_MSG_UNANNOUNCE          = 0x9,  /* Alias for PUBLISH_NAMESPACE_DONE */
    XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE = 0x9,   /* Per draft-ietf-moq-transport */
    XQC_MOQ_MSG_UNSUBSCRIBE         = 0xA,
    XQC_MOQ_MSG_SUBSCRIBE_DONE      = 0xB,
    XQC_MOQ_MSG_ANNOUNCE_CANCEL     = 0xC,
    XQC_MOQ_MSG_TRACK_STATUS        = 0xD,
    XQC_MOQ_MSG_TRACK_STATUS_OK     = 0xE,
    XQC_MOQ_MSG_TRACK_STATUS_ERROR  = 0xF,
    XQC_MOQ_MSG_GOAWAY              = 0x10,
    XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE = 0x11,
    XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK = 0x12,
    XQC_MOQ_MSG_FETCH               = 0x16,
    XQC_MOQ_MSG_REQUESTS_BLOCKED    = 0x1A,
    XQC_MOQ_MSG_PUBLISH             = 0x1D, /* PUBLISH message type */
    XQC_MOQ_MSG_PUBLISH_OK          = 0x1E, /* PUBLISH_OK message type */
    XQC_MOQ_MSG_PUBLISH_ERROR       = 0x1F, /* PUBLISH_ERROR message type */
    // XQC_MOQ_MSG_CLIENT_SETUP        = 0x40, // draft-10 and before
    // XQC_MOQ_MSG_SERVER_SETUP        = 0x41, // draft-10 and before
    XQC_MOQ_MSG_CLIENT_SETUP        = 0x20, // draft-11 and later
    XQC_MOQ_MSG_SERVER_SETUP        = 0x21, // draft-11 and later
    XQC_MOQ_MSG_STREAM_HEADER_TRACK = 0x50,
    XQC_MOQ_MSG_STREAM_HEADER_GROUP = 0x51,
    XQC_MOQ_MSG_MAX_REQUEST_ID      = 0x15,
    XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE = 0x14,

    /* Phony message types */
    XQC_MOQ_MSG_TRACK_STREAM_OBJECT = 0xA0,
    XQC_MOQ_MSG_GROUP_STREAM_OBJECT = 0xA1,
    
} xqc_moq_msg_type_t;

typedef enum {
    // from draft-11 - OBJECT_DATAGRAM 类型 (0x0-0x3)
    XQC_MOQ_OBJECT_DATAGRAM             = 0x0,  // without End of Group, without Extensions
    XQC_MOQ_OBJECT_DATAGRAM_EXT         = 0x1,  // without End of Group, with Extensions
    XQC_MOQ_OBJECT_DATAGRAM_EOG         = 0x2,  // with End of Group, without Extensions
    XQC_MOQ_OBJECT_DATAGRAM_EOG_EXT     = 0x3,  // with End of Group, with Extensions
    // OBJECT_DATAGRAM_STATUS 类型 (0x4-0x5)
    XQC_MOQ_OBJECT_DATAGRAM_STATUS      = 0x4,  // without Extensions
    XQC_MOQ_OBJECT_DATAGRAM_STATUS_EXT  = 0x5,  // with Extensions
    
    // SUBGROUP_HEADER 类型 (0x10-0x1D) - 支持12种不同的subgroup header类型
    XQC_MOQ_SUBGROUP_0x10               = 0x10, // No Subgroup ID Field, Subgroup ID = 0, No Extensions, No End of Group
    XQC_MOQ_SUBGROUP_0x11               = 0x11, // No Subgroup ID Field, Subgroup ID = 0, With Extensions, No End of Group  
    XQC_MOQ_SUBGROUP_0x12               = 0x12, // No Subgroup ID Field, Subgroup ID = First Object ID, No Extensions, No End of Group
    XQC_MOQ_SUBGROUP_0x13               = 0x13, // No Subgroup ID Field, Subgroup ID = First Object ID, With Extensions, No End of Group
    XQC_MOQ_SUBGROUP_0x14               = 0x14, // With Subgroup ID Field, No Extensions, No End of Group
    XQC_MOQ_SUBGROUP_0x15               = 0x15, // With Subgroup ID Field, With Extensions, No End of Group
    XQC_MOQ_SUBGROUP_0x18               = 0x18, // No Subgroup ID Field, Subgroup ID = 0, No Extensions, With End of Group
    XQC_MOQ_SUBGROUP_0x19               = 0x19, // No Subgroup ID Field, Subgroup ID = 0, With Extensions, With End of Group
    XQC_MOQ_SUBGROUP_0x1A               = 0x1A, // No Subgroup ID Field, Subgroup ID = First Object ID, No Extensions, With End of Group
    XQC_MOQ_SUBGROUP_0x1B               = 0x1B, // No Subgroup ID Field, Subgroup ID = First Object ID, With Extensions, With End of Group
    XQC_MOQ_SUBGROUP_0x1C               = 0x1C, // With Subgroup ID Field, No Extensions, With End of Group
    XQC_MOQ_SUBGROUP_0x1D               = 0x1D, // With Subgroup ID Field, With Extensions, With End of Group
    
    // 默认推荐的SUBGROUP_HEADER类型 (与之前行为兼容：需要subgroup_id，不需要extensions和end_of_group)
    XQC_MOQ_SUBGROUP_DEFAULT            = 0x14, // With Subgroup ID Field, No Extensions, No End of Group (recommended default)
    
    // 旧的兼容性类型
    XQC_MOQ_SUBGROUP                    = 0x0A, // without extension header (deprecated, use specific types above)
    XQC_MOQ_SUBGROUP_EXT                = 0x09, // with extension header (deprecated, use specific types above)
    XQC_MOQ_SUBGROUP_OBJECT             = 0xA3, // enable for draft-11 and later, msg type is useless for transport
    XQC_MOQ_SUBGROUP_OBJECT_EXT         = 0xA4, // enable for draft-11 and later, msg type is useless for transport
    // from draft-05
    XQC_MOQ_STREAM_HEADER_GROUP     = 0x4, // remain for draft-05
    XQC_MOQ_FETCH_HEADER            = 0x5, // TODO, not implemented yet
    // XQC_MOQ_SUBGROUP                = 0x4, // deprecated in draft-11
}xqc_moq_data_stream_type_t;

typedef struct {
    uint64_t                    type;
    uint64_t                    length;
    // uint8_t                     *value;
    uint64_t                     *value;
} xqc_moq_message_parameter_t;

typedef struct xqc_moq_msg_base_s {
    // xqc_moq_msg_type_t (*type)();
    xqc_int_t (*type)();
    xqc_int_t (*encode_len)(struct xqc_moq_msg_base_s *msg_base);
    xqc_int_t (*encode)(struct xqc_moq_msg_base_s *msg_base, uint8_t *buf, size_t buf_cap);
    xqc_int_t (*decode)(uint8_t *buf, size_t buf_len, uint8_t stream_fin, struct xqc_moq_decode_msg_ctx_s *msg_ctx,
                        struct xqc_moq_msg_base_s *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);
    void (*on_msg)(struct xqc_moq_session_s *session, struct xqc_moq_stream_s *moq_stream, struct xqc_moq_msg_base_s *msg_base);
} xqc_moq_msg_base_t;

typedef struct xqc_moq_subscribe_msg_v05_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    length; /* Length field for v11 */
    uint64_t                    subscribe_id;
    uint64_t                    track_alias;
    xqc_moq_msg_track_namespace_t *track_namespace;
    char                        *track_name;
    size_t                      track_name_len;
    uint8_t                     subscriber_priority; /* Corrected to uint8_t for v11 */
    uint8_t                     group_order; /* Corrected to uint8_t for v11 */
    uint8_t                     forward; /* New Forward field for v11 */
    uint64_t                    filter_type;
    uint64_t                    start_group_id;
    uint64_t                    start_object_id;
    uint64_t                    end_group_id;
    uint64_t                    end_object_id;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_subscribe_msg_t_v05;

typedef struct xqc_moq_subscribe_msg_v13_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    length; /* Length field for v11 */
    uint64_t                    request_id; /* request_id for v11 */
    xqc_moq_msg_track_namespace_t *track_namespace;
    char                        *track_name;
    size_t                      track_name_len;
    uint8_t                     subscriber_priority; /* Corrected to uint8_t for v11 */
    uint8_t                     group_order; /* Corrected to uint8_t for v11 */
    uint8_t                     forward; /* New Forward field for v11 */
    uint64_t                    filter_type;
    uint64_t                    start_group_id;
    uint64_t                    start_object_id;
    uint64_t                    end_group_id;
    uint64_t                    end_object_id;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    uint64_t                    track_alias; // ONLY for test draft-11
} xqc_moq_subscribe_msg_t_v13;

typedef struct xqc_moq_subscribe_namespace_msg_s {
    xqc_moq_msg_base_t msg_base;
    uint64_t request_id;
    uint64_t track_namespace_prefix_num;
    xqc_moq_msg_track_namespace_t *track_namespace_prefix;
    uint64_t params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_subscribe_namespace_msg_t;

typedef struct xqc_moq_unsubscribe_namespace_msg_s {
    xqc_moq_msg_base_t msg_base;
    xqc_moq_msg_track_namespace_t *track_namespace_prefix;
} xqc_moq_unsubscribe_namespace_msg_t;

/* PUBLISH_NAMESPACE messages */
typedef struct xqc_moq_publish_namespace_msg_s {
    xqc_moq_msg_base_t msg_base;
    uint64_t request_id;
    xqc_moq_msg_track_namespace_t *track_namespace; /* namespace being published */
    uint64_t params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_publish_namespace_msg_t;

typedef struct xqc_moq_publish_namespace_done_msg_s {
    xqc_moq_msg_base_t msg_base;
    xqc_moq_msg_track_namespace_t *track_namespace; /* namespace being withdrawn */
} xqc_moq_publish_namespace_done_msg_t;

typedef struct xqc_moq_publish_namespace_ok_msg_s {
    xqc_moq_msg_base_t msg_base;
    uint64_t request_id;
} xqc_moq_publish_namespace_ok_msg_t;

typedef struct xqc_moq_publish_namespace_error_msg_s {
    xqc_moq_msg_base_t msg_base;
    uint64_t request_id;
    uint64_t error_code;
    uint64_t reason_len;
    char *reason;
} xqc_moq_publish_namespace_error_msg_t;


typedef struct xqc_moq_track_status_msg_s {
    xqc_moq_msg_base_t msg_base;
    xqc_moq_msg_track_namespace_t *track_namespace;
    uint64_t request_id;
    uint64_t track_name_len;
    char *track_name;
    uint8_t subscriber_priority;
    uint8_t group_order;
    uint8_t forward;
    uint64_t filter_type;
    uint64_t start_location;
    uint64_t end_group;
    uint64_t params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_track_status_msg_t;


typedef struct xqc_moq_track_status_ok_msg_s {
    xqc_moq_msg_base_t msg_base;
    uint64_t request_id;
    uint64_t track_alias;
    uint64_t expires;
    uint8_t group_order;
    uint8_t content_exists;
    uint64_t largest_location;
    uint64_t params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_track_status_ok_msg_t;

typedef struct xqc_moq_track_status_error_msg_s {
    xqc_moq_msg_base_t msg_base;
    uint64_t request_id;
    uint64_t error_code;
    uint64_t error_reason_len;
    char *error_reason;
} xqc_moq_track_status_error_msg_t;


typedef struct xqc_moq_publish_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    length; /* Length field for v11 */
    uint64_t                    request_id;
    xqc_moq_msg_track_namespace_t *track_namespace;
    uint64_t                    track_name_len;
    char                        *track_name;
    uint64_t                    track_alias;
    uint8_t                     group_order; /* Group Order (8 bits) */
    uint8_t                     content_exists; /* ContentExists (8 bits) */
    uint64_t                    largest_group_id; /* Only present if content_exists is 1 */
    uint64_t                    largest_object_id; /* Only present if content_exists is 1 */
    uint8_t                     forward; /* Forward (8 bits) */
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_publish_msg_t;

typedef struct xqc_moq_publish_ok_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_publish_ok_msg_t;

typedef struct xqc_moq_publish_error_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id;
    uint64_t                    error_code;
    uint64_t                    reason_len;
    char                        *reason;
} xqc_moq_publish_error_msg_t;

typedef struct xqc_moq_subscribe_ok_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    track_alias; /* Track Alias for v11 */
    uint64_t                    expire_ms;
    uint8_t                     group_order;
    uint8_t                     content_exist; /* Renamed for clarity (was content_exist) */
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

typedef struct xqc_moq_object_datagram_s {
    uint64_t                    type;                    /* Type 0x0-0x3：OBJECT_DATAGRAM */
    uint64_t                    track_alias;
    uint64_t                    group_id;
    uint64_t                    object_id;
    uint8_t                     publisher_priority;
    uint64_t                    extension_headers_length; /* 仅当 Extensions Present 时有效 */
    uint8_t                     *extension_headers;
    size_t                      payload_len;
    uint8_t                     *payload;
    /* 辅助字段 */
    xqc_bool_t                  end_of_group;           /* 是否为组的最后一个对象 */
    xqc_bool_t                  extensions_present;     /* 是否包含扩展头 */
} xqc_moq_object_datagram_t;

/* OBJECT_DATAGRAM_STATUS 结构：独立的状态消息类型 */
typedef struct xqc_moq_object_datagram_status_s {
    uint64_t                    type;                    /* Type 0x4-0x5：OBJECT_DATAGRAM_STATUS */
    uint64_t                    track_alias;
    uint64_t                    group_id;
    uint64_t                    object_id;
    uint8_t                     publisher_priority;
    uint64_t                    extension_headers_length; /* 仅当 Extensions Present 时有效 */
    uint8_t                     *extension_headers;
    uint64_t                    object_status;           /* Object Status 字段 */
    /* 辅助字段 */
    xqc_bool_t                  extensions_present;     /* 是否包含扩展头 */
} xqc_moq_object_datagram_status_t;

typedef struct xqc_moq_subgroup_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    type;               // SUBGROUP_HEADER type (0x10-0x1D)
    uint64_t                    track_alias;
    uint64_t                    group_id;
    uint64_t                    subgroup_id;       // Only present for certain types
    uint64_t                    publish_priority;
    // 辅助字段，用于确定消息格式
    xqc_bool_t                  subgroup_id_present;   // 是否包含显式的Subgroup ID字段
    xqc_bool_t                  extensions_present;    // 是否包含Extension Headers
    xqc_bool_t                  end_of_group;          // 是否包含End of Group标识
    uint64_t                    first_object_id;       // 当Subgroup ID = First Object ID时使用
} xqc_moq_subgroup_msg_t;

// object_msgs that follows the subgroup_msg_ext should take extension header
typedef struct xqc_moq_subgroup_msg_ext_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    track_alias;
    uint64_t                    group_id;
    uint64_t                    subgroup_id;
    uint64_t                    publish_priority;
} xqc_moq_subgroup_msg_ext_t; 

typedef struct xqc_moq_subgroup_object_msg_s {
    xqc_moq_msg_base_t          msg_base;
    xqc_moq_subgroup_msg_t      *subgroup_header;
    uint64_t                    object_id;
    uint64_t                    extension_header_len;
    uint64_t                    payload_len;
    xqc_moq_object_status_t     object_status;
    uint8_t                     *payload;
} xqc_moq_subgroup_object_msg_t;

typedef struct xqc_moq_subgroup_object_msg_ext_s{
    xqc_moq_msg_base_t          msg_base;
    xqc_moq_subgroup_msg_t      *subgroup_header;
    uint64_t                    object_id;
    uint64_t                    extension_header_len;
    char                        *extension_header;
    uint64_t                    payload_len;
    uint64_t                    object_status;
    uint8_t                     *payload;
} xqc_moq_subgroup_object_msg_ext_t;

typedef struct xqc_moq_announce_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id; /* Request ID for the announce */
    xqc_moq_msg_track_namespace_t *track_namespace;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_announce_msg_t;

typedef struct xqc_moq_announce_ok_msg_s {
    xqc_moq_msg_base_t msg_base;
    uint64_t                    request_id; /* Request ID this message is replying to */
} xqc_moq_announce_ok_msg_t;

typedef enum {
    XQC_MOQ_ANNOUNCE_ERROR_INTERNAL_ERROR       = 0x0,
    XQC_MOQ_ANNOUNCE_ERROR_UNAUTHORIZED         = 0x1,
    XQC_MOQ_ANNOUNCE_ERROR_TIMEOUT              = 0x2,
    XQC_MOQ_ANNOUNCE_ERROR_NOT_SUPPORTED        = 0x3,
    XQC_MOQ_ANNOUNCE_ERROR_UNINTERESTED         = 0x4,
    XQC_MOQ_ANNOUNCE_ERROR_MALFORMED_AUTH_TOKEN = 0x10,
    XQC_MOQ_ANNOUNCE_ERROR_EXPIRED_AUTH_TOKEN   = 0x12,
} xqc_moq_announce_error_code_t;

typedef struct xqc_moq_announce_error_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    request_id; /* Request ID this message is replying to */
    uint64_t                    error_code;
    uint64_t                    reason_phrase_len;
    char                        *reason_phrase;
} xqc_moq_announce_error_msg_t;

typedef void (*xqc_moq_on_session_setup_pt)(xqc_moq_user_session_t *user_session, char *extdata);

typedef void (*xqc_moq_on_datachannel_pt)(xqc_moq_user_session_t *user_session);

typedef void (*xqc_moq_on_datachannel_msg_pt)(xqc_moq_user_session_t *user_session, uint8_t *msg, size_t msg_len);

typedef void (*xqc_moq_on_subscribe_v05_pt)(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v05 *msg);

typedef void (*xqc_moq_on_subscribe_v13_pt)(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v13 *msg);

typedef void (*xqc_moq_on_request_keyframe_pt)(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track);

typedef void (*xqc_moq_on_subscribe_ok_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_ok_msg_t *subscribe_ok);

typedef void (*xqc_moq_on_subscribe_error_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_error_msg_t *subscribe_error);

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
typedef void (*xqc_moq_on_bitrate_change_pt)(xqc_moq_user_session_t *user_session, uint64_t bitrate);

typedef void (*xqc_moq_on_datagram_pt)(xqc_moq_user_session_t *user_session, xqc_moq_object_datagram_t *object_datagram);

typedef void (*xqc_moq_on_datagram_status_pt)(xqc_moq_user_session_t *user_session, xqc_moq_object_datagram_status_t *object_datagram_status);

typedef void (*xqc_moq_on_goaway_pt)(xqc_moq_user_session_t *user_session, xqc_moq_goaway_msg_t *goaway);

/**
 * @brief There are two ways to get the target bitrate. 
 * 1. Call xqc_moq_target_bitrate before encoding. 
 * 2. Register the xqc_moq_on_bitrate_change_pt callback. A callback notification occurs when the target bitrate changes
 */
typedef void (*xqc_moq_on_bitrate_change_pt)(xqc_moq_user_session_t *user_session, uint64_t bitrate);

typedef void (*xqc_moq_on_track_status_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_track_status_msg_t *track_status);
typedef void (*xqc_moq_on_track_status_ok_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_track_status_ok_msg_t *track_status_ok);
typedef void (*xqc_moq_on_track_status_error_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_track_status_error_msg_t *track_status_error);
typedef void (*xqc_moq_on_max_request_id_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_max_request_id_msg_t *max_request_id);

typedef void (*xqc_moq_on_announce_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_announce_msg_t *announce);

typedef void (*xqc_moq_on_subgroup_object_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_subgroup_object_msg_t *subgroup_object);

typedef void (*xqc_moq_on_announce_ok_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_announce_ok_msg_t *announce_ok);

typedef void (*xqc_moq_on_announce_error_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_announce_error_msg_t *announce_error);

typedef void (*xqc_moq_on_subscribe_namespace_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace);

typedef void (*xqc_moq_on_subscribe_namespace_ok_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok);

typedef void (*xqc_moq_on_unsubscribe_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_unsubscribe_msg_t *unsubscribe);

typedef void (*xqc_moq_on_publish_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_publish_msg_t *publish);

typedef void (*xqc_moq_on_publish_ok_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_publish_ok_msg_t *publish_ok);

typedef void (*xqc_moq_on_publish_error_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_publish_error_msg_t *publish_error);

typedef void (*xqc_moq_on_publish_namespace_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_publish_namespace_msg_t *publish_ns);

typedef void (*xqc_moq_on_publish_namespace_done_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_publish_namespace_done_msg_t *publish_ns_done);

typedef void (*xqc_moq_on_publish_namespace_ok_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_publish_namespace_ok_msg_t *ok);

typedef void (*xqc_moq_on_publish_namespace_error_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_publish_namespace_error_msg_t *err);

typedef void (*xqc_moq_on_track_status_pt)(xqc_moq_user_session_t *user_session,
    xqc_moq_track_status_msg_t *track_status);

typedef struct {
    xqc_moq_on_session_setup_pt     on_session_setup; /* Required */
    xqc_moq_on_datachannel_pt       on_datachannel; /* Required */
    xqc_moq_on_datachannel_msg_pt   on_datachannel_msg; /* Required */
    /* For Publisher */
    xqc_moq_on_subscribe_v05_pt     on_subscribe_v05; /* Required */
    xqc_moq_on_subscribe_v13_pt     on_subscribe_v13; /* Required */
    xqc_moq_on_request_keyframe_pt  on_request_keyframe; /* Required */
    xqc_moq_on_bitrate_change_pt    on_bitrate_change; /* Optional */
    /* For Subscriber */
    xqc_moq_on_subscribe_ok_pt      on_subscribe_ok; /* Required */
    xqc_moq_on_subscribe_error_pt   on_subscribe_error; /* Required */
    xqc_moq_on_catalog_pt           on_catalog; /* Required */
    xqc_moq_on_video_frame_pt       on_video; /* Required */
    xqc_moq_on_audio_frame_pt       on_audio; /* Required */
    xqc_moq_on_datagram_pt          on_datagram; /* Optional */
    xqc_moq_on_datagram_status_pt   on_datagram_status; /* Optional */
    xqc_moq_on_goaway_pt            on_goaway; /* Optional */
    xqc_moq_on_track_status_pt      on_track_status; /* Optional */
    xqc_moq_on_track_status_ok_pt   on_track_status_ok; /* Optional */
    xqc_moq_on_track_status_error_pt on_track_status_error; /* Optional */
    xqc_moq_on_max_request_id_pt    on_max_request_id; /* Optional */
    xqc_moq_on_announce_pt          on_announce; /* Optional */
    xqc_moq_on_announce_ok_pt       on_announce_ok; /* Optional */
    xqc_moq_on_announce_error_pt   on_announce_error; /* Optional */
    xqc_moq_on_subgroup_object_pt   on_subgroup_object; /* Optional */
    xqc_moq_on_subscribe_namespace_pt on_subscribe_namespace; /* Optional */
    xqc_moq_on_subscribe_namespace_ok_pt on_subscribe_namespace_ok; /* Optional */
    xqc_moq_on_unsubscribe_pt        on_unsubscribe; /* Optional */
    xqc_moq_on_publish_pt            on_publish; /* Optional */
    xqc_moq_on_publish_ok_pt        on_publish_ok; /* Optional */
    xqc_moq_on_publish_error_pt     on_publish_error; /* Optional */
    xqc_moq_on_publish_namespace_pt on_publish_namespace; /* Optional */
    xqc_moq_on_publish_namespace_done_pt on_publish_namespace_done; /* Optional */
    xqc_moq_on_publish_namespace_ok_pt on_publish_namespace_ok; /* Optional */
    xqc_moq_on_publish_namespace_error_pt on_publish_namespace_error; /* Optional */
} xqc_moq_session_callbacks_t;

typedef enum {
    XQC_MOQ_SUPPORTED_VERSION_05 = 0xff000005, 
    XQC_MOQ_SUPPORTED_VERSION_11 = 0xff00000B, 
    XQC_MOQ_SUPPORTED_VERSION_13 = 0xff00000D,
    XQC_MOQ_SUPPORTED_VERSION_14 = 0xff00000E,
} xqc_moq_supported_version_t;

XQC_EXPORT_PUBLIC_API
void xqc_moq_init_alpn(xqc_engine_t *engine, xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type);

XQC_EXPORT_PUBLIC_API
void xqc_moq_init_alpn_by_custom(xqc_engine_t *engine, xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type, xqc_moq_supported_version_t version);

/**
 * @param extdata The client can send extdata when creating a session. 
 *                This extdata will be received by the server in the on_session_setup callback.
 * @param version The version of the MOQ protocol to use. Client must set the version when create session.
 *                Server's session will be set by ALPN version negotiation callbacks.
 */
XQC_EXPORT_PUBLIC_API
xqc_moq_session_t *xqc_moq_session_create(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t type, xqc_moq_supported_version_t version, xqc_moq_role_t role, xqc_moq_session_callbacks_t, char *extdata);

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

// XQC_EXPORT_PUBLIC_API
// xqc_int_t xqc_moq_subscribe(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
//     xqc_moq_filter_type_t filter_type, uint64_t start_group_id, uint64_t start_object_id,
//     uint64_t end_group_id, uint64_t end_object_id, char *authinfo);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_v05(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
    xqc_moq_filter_type_t filter_type, uint64_t start_group_id, uint64_t start_object_id,
    uint64_t end_group_id, uint64_t end_object_id, char *authinfo);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_v13(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
    xqc_moq_filter_type_t filter_type, uint64_t start_group_id, uint64_t start_object_id,
    uint64_t end_group_id, uint64_t end_object_id, char *authinfo);

// XQC_EXPORT_PUBLIC_API
// xqc_int_t xqc_moq_unsubscribe(xqc_moq_session_t *session, const char *track_namespace, const char *track_name);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_latest(xqc_moq_session_t *session, const char *track_namespace, const char *track_name);

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

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subgroup(xqc_moq_session_t *session, xqc_moq_subgroup_msg_t *subgroup,
    xqc_int_t subgroup_object_num, xqc_moq_subgroup_object_msg_t **subgroup_object);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_announce(xqc_moq_session_t *session, xqc_moq_announce_msg_t *announce_msg);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_announce_ok(xqc_moq_session_t *session, xqc_moq_announce_ok_msg_t *announce_ok);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_encode_cid(uint32_t token, const uint8_t *key, uint8_t cid_len, uint8_t *encrypted_cid);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_decode_cid(const uint8_t *encrypted_cid, uint8_t cid_len, const uint8_t *key, uint32_t *token);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_object_datagram(xqc_moq_session_t *session, uint64_t track_alias,
    uint64_t group_id, uint64_t object_id, uint8_t publisher_priority, uint8_t *payload, size_t payload_len);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_object_datagram_ext(xqc_moq_session_t *session, xqc_moq_object_datagram_t *object_datagram);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_object_datagram_status(xqc_moq_session_t *session, xqc_moq_object_datagram_status_t *object_datagram_status);

XQC_EXPORT_PUBLIC_API
void xqc_moq_msg_free_object_datagram(xqc_moq_object_datagram_t *object_datagram);

XQC_EXPORT_PUBLIC_API
void xqc_moq_msg_free_object_datagram_status(xqc_moq_object_datagram_status_t *object_datagram_status);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_datachannel(xqc_moq_session_t *session);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_catalog(xqc_moq_session_t *session);

XQC_EXPORT_PUBLIC_API 
xqc_int_t xqc_moq_subscribe_done(xqc_moq_session_t *session, uint64_t subscribe_id, 
    xqc_moq_subscribe_done_status_t status_code, uint64_t stream_count, char *reason, size_t reason_len);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_cancel_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id, xqc_int_t is_local);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_goaway(xqc_moq_session_t *session, uint64_t new_URI_len, char *new_URI);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_namespace(xqc_moq_session_t *session, xqc_moq_subscribe_namespace_msg_t *subscribe_namespace);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_namespace_ok(xqc_moq_session_t *session, xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_publish(xqc_moq_session_t *session, xqc_moq_publish_msg_t *publish);

/* PUBLISH_NAMESPACE APIs */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_publish_namespace(xqc_moq_session_t *session, xqc_moq_publish_namespace_msg_t *publish_ns);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_publish_namespace_done(xqc_moq_session_t *session, xqc_moq_publish_namespace_done_msg_t *publish_ns_done);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_track_status(xqc_moq_session_t *session, xqc_moq_track_status_msg_t *track_status);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_track_status_ok(xqc_moq_session_t *session, xqc_moq_track_status_ok_msg_t *track_status_ok);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_track_status_error(xqc_moq_session_t *session, xqc_moq_track_status_error_msg_t *track_status_error);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_v13(xqc_moq_session_t *session, xqc_moq_subscribe_msg_t_v13 *subscribe_msg);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_subscribe_namespace(xqc_moq_session_t *session, xqc_moq_subscribe_namespace_msg_t *subscribe_namespace);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_write_unsubscribe_namespace(xqc_moq_session_t *session, xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace);

/* Priority feature config (Phase 1) */
XQC_EXPORT_PUBLIC_API
void xqc_moq_set_priority_config(xqc_moq_session_t *session, int enabled, int enforce);

/* Namespace subscription convenience API */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_subscribe_namespace_by_path(
    xqc_moq_session_t *session,
    const char **namespace_segments,
    uint64_t segment_count,
    uint64_t *out_request_id);

#ifdef __cplusplus
}
#endif

#endif /* _XQC_MOQ_H_INCLUDED_ */
