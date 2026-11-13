/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef _XQC_MOQT_H_INCLUDED_
#define _XQC_MOQT_H_INCLUDED_

#include <xquic/xquic.h>
#include <moq/xqc_moq.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Native QUIC version selection: draft-22 section 6.2. */
#define XQC_MOQT_ALPN_DRAFT_22 "moqt-22"

typedef enum {
    XQC_MOQT_VERSION_DRAFT_22 = 22,
} xqc_moqt_version_t;

typedef struct xqc_moqt_kv_s xqc_moqt_kv_t;
typedef struct xqc_moqt_session_s xqc_moqt_session_t;
typedef struct xqc_moqt_request_s xqc_moqt_request_t;
typedef struct xqc_moqt_stream_s xqc_moqt_stream_t;
typedef struct xqc_moqt_subscription_s xqc_moqt_subscription_t;
typedef struct xqc_moqt_fetch_s xqc_moqt_fetch_t;

typedef struct {
    xqc_moqt_version_t      version;
    const xqc_moqt_kv_t    *setup_options;
    size_t                  setup_option_count;
    size_t                  max_streams;
    size_t                  max_buffered_bytes;
    xqc_usec_t              timeout; /* SETUP/partial message timeout in us. */
} xqc_moqt_config_t;

/* Unsupported versions return -XQC_EPARAM without changing config. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_config_init(xqc_moqt_config_t *config,
    xqc_moqt_version_t version);

/* Returns a static ALPN string, or NULL for an unsupported configuration. */
XQC_EXPORT_PUBLIC_API
const char *xqc_moqt_config_alpn(const xqc_moqt_config_t *config);

/* Copies connection callbacks; legacy xqc_moq_* registrations are separate. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_init_alpn(xqc_engine_t *engine,
    const xqc_moqt_config_t *config, const xqc_conn_callbacks_t *conn_cbs);

/*
 * Requires local DATAGRAM support. Until explicit MoQT resumption is added,
 * ticket/transport-parameter cache input is rejected. Other arguments and
 * the engine-owned returned CID follow xqc_connect(); failure returns NULL.
 */
XQC_EXPORT_PUBLIC_API
const xqc_cid_t *xqc_moqt_connect(xqc_engine_t *engine,
    const xqc_moqt_config_t *config, const xqc_conn_settings_t *settings,
    const unsigned char *token, unsigned token_len, const char *server_host,
    const xqc_conn_ssl_config_t *ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data);

/* Current wire contract: draft-ietf-moq-transport-22 sections 8 and 9. */
#define XQC_MOQT_NAMESPACE_MAX_FIELDS 32
#define XQC_MOQT_NAME_MAX_LEN 4096
#define XQC_MOQT_MESSAGE_MAX_BODY UINT16_MAX
#define XQC_MOQT_KV_MAX_VALUE UINT16_MAX

typedef enum {
    XQC_MOQT_MSG_REQUEST_UPDATE       = 0x02,
    XQC_MOQT_MSG_SUBSCRIBE            = 0x03,
    XQC_MOQT_MSG_SUBSCRIBE_OK         = 0x04,
    XQC_MOQT_MSG_REQUEST_ERROR        = 0x05,
    XQC_MOQT_MSG_PUBLISH_NAMESPACE    = 0x06,
    XQC_MOQT_MSG_REQUEST_OK           = 0x07,
    XQC_MOQT_MSG_NAMESPACE            = 0x08,
    XQC_MOQT_MSG_PUBLISH_DONE         = 0x0b,
    XQC_MOQT_MSG_TRACK_STATUS         = 0x0d,
    XQC_MOQT_MSG_NAMESPACE_DONE       = 0x0e,
    XQC_MOQT_MSG_PUBLISH_SKIPPED      = 0x0f,
    XQC_MOQT_MSG_GOAWAY               = 0x10,
    XQC_MOQT_MSG_FETCH                = 0x16,
    XQC_MOQT_MSG_FETCH_OK             = 0x18,
    XQC_MOQT_MSG_PUBLISH              = 0x1d,
    XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY = 0x22,
    XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE  = 0x50,
    XQC_MOQT_MSG_SUBSCRIBE_TRACKS     = 0x51,
    XQC_MOQT_MSG_SETUP                = 0x2f00,
} xqc_moqt_message_type_t;

/* Decoded iovec storage is borrowed and read-only, despite void * bases. */
typedef struct {
    size_t          count;
    struct iovec    fields[XQC_MOQT_NAMESPACE_MAX_FIELDS];
} xqc_moqt_namespace_t;

typedef struct {
    uint64_t    group_id;
    uint64_t    object_id;
} xqc_moqt_location_t;

typedef enum {
    XQC_MOQT_OBJECT_NORMAL    = 0,
    XQC_MOQT_OBJECT_END_GROUP = 3,
    XQC_MOQT_OBJECT_END_TRACK = 4,
} xqc_moqt_object_status_t;

typedef enum {
    XQC_MOQT_RANGE_NONE,
    XQC_MOQT_RANGE_NONEXISTENT,
    XQC_MOQT_RANGE_UNKNOWN,
    XQC_MOQT_RANGE_TIMEOUT,
} xqc_moqt_range_t;

/* Borrowed bytes. Datagram objects have no subgroup and carry one payload. */
typedef struct {
    uint64_t                    group_id;
    uint64_t                    object_id;
    uint64_t                    subgroup_id; /* Only valid when !datagram. */
    xqc_moqt_object_status_t    status;
    xqc_moqt_range_t            range; /* FETCH range endpoint. */
    struct iovec                properties;
    struct iovec                payload;
    uint64_t                    payload_length;
    uint64_t                    payload_offset;
    uint8_t                     priority;
    unsigned                    datagram:1;
    unsigned                    end_of_group:1;
    unsigned                    first_in_subgroup:1;
} xqc_moqt_object_t;

typedef enum {
    XQC_MOQT_GROUP_ASCENDING  = 1,
    XQC_MOQT_GROUP_DESCENDING = 2,
} xqc_moqt_group_order_t;

typedef enum {
    XQC_MOQT_FILTER_NONE           = 0,
    XQC_MOQT_FILTER_RELATIVE_START = 1,
    XQC_MOQT_FILTER_ABSOLUTE_START = 2,
    XQC_MOQT_FILTER_GROUP_END      = 3,
    XQC_MOQT_FILTER_ABSOLUTE_RANGE = 4,
    XQC_MOQT_FILTER_NEXT_OBJECT    = 5,
} xqc_moqt_location_filter_t;

/* A FETCH response covers start..end inclusively, in group_order. */
typedef struct {
    xqc_moqt_location_t    start;
    xqc_moqt_location_t    end;
    uint64_t               request_id;
    uint64_t               fill_timeout;
    uint8_t                group_order;
    uint8_t                subscriber_priority;
    unsigned               end_of_track:1;
    unsigned               has_fill_timeout:1;
} xqc_moqt_fetch_info_t;

#define XQC_MOQT_MAX_PARAMETERS 64
#define XQC_MOQT_MAX_REASON 1024

typedef enum {
    XQC_MOQT_ERROR_SESSION,
    XQC_MOQT_ERROR_REQUEST,
    XQC_MOQT_ERROR_PUBLISH_DONE,
    XQC_MOQT_ERROR_RESET,
} xqc_moqt_error_context_t;

typedef struct {
    xqc_moqt_error_context_t    context;
    uint64_t                    code;
    uint64_t                    normalized_code;
} xqc_moqt_error_t;

/* Message bytes and parameter values are borrowed, including decoded views. */
typedef struct {
    uint64_t                    type;
    struct iovec                body;
    uint64_t                    request_id;
    xqc_moqt_namespace_t        track_namespace;
    struct iovec                track_name;
    uint64_t                    track_alias;
    size_t                      parameter_count;
    xqc_moq_message_parameter_t parameters[XQC_MOQT_MAX_PARAMETERS];
    struct iovec                properties;
    xqc_moqt_error_t            error;
    uint64_t                    retry_interval;
    uint64_t                    timeout_ms;
    struct iovec                reason;
    struct iovec                uri;
    uint64_t                    end_group;
    uint64_t                    end_object;
    uint64_t                    stream_count;
    uint8_t                     end_of_track;
} xqc_moqt_message_t;

typedef enum {
    XQC_MOQT_PARAM_OBJECT_DELIVERY_TIMEOUT   = 0x02,
    XQC_MOQT_PARAM_AUTHORIZATION_TOKEN       = 0x03,
    XQC_MOQT_PARAM_RENDEZVOUS_TIMEOUT        = 0x04,
    XQC_MOQT_PARAM_SUBGROUP_DELIVERY_TIMEOUT = 0x06,
    XQC_MOQT_PARAM_EXPIRES                   = 0x08,
    XQC_MOQT_PARAM_LARGEST_OBJECT            = 0x09,
    XQC_MOQT_PARAM_FILL_TIMEOUT              = 0x0a,
    XQC_MOQT_PARAM_FORWARD                   = 0x10,
    XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY       = 0x20,
    XQC_MOQT_PARAM_LOCATION_FILTER           = 0x21,
    XQC_MOQT_PARAM_GROUP_ORDER               = 0x22,
    XQC_MOQT_PARAM_FILL_PARAMETERS           = 0x23,
    XQC_MOQT_PARAM_SUBGROUP_FILTER           = 0x25,
    XQC_MOQT_PARAM_OBJECTID_FILTER           = 0x26,
    XQC_MOQT_PARAM_PRIORITY_FILTER           = 0x27,
    XQC_MOQT_PARAM_OBJECT_PROPERTY_FILTER    = 0x28,
    XQC_MOQT_PARAM_TRACK_PROPERTY_FILTER     = 0x29,
    XQC_MOQT_PARAM_NEW_GROUP_REQUEST         = 0x32,
    XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX    = 0x34,
    XQC_MOQT_PARAM_INCLUDE_PROPERTIES        = 0x35,
} xqc_moqt_parameter_type_t;

typedef enum {
    XQC_MOQT_REQUEST_INTERNAL_ERROR        = 0x00,
    XQC_MOQT_REQUEST_UNAUTHORIZED          = 0x01,
    XQC_MOQT_REQUEST_TIMEOUT               = 0x02,
    XQC_MOQT_REQUEST_NOT_SUPPORTED         = 0x03,
    XQC_MOQT_REQUEST_MALFORMED_AUTH_TOKEN  = 0x04,
    XQC_MOQT_REQUEST_EXPIRED_AUTH_TOKEN    = 0x05,
    XQC_MOQT_REQUEST_GOING_AWAY            = 0x06,
    XQC_MOQT_REQUEST_EXCESSIVE_LOAD        = 0x09,
    XQC_MOQT_REQUEST_DOES_NOT_EXIST        = 0x10,
    XQC_MOQT_REQUEST_INVALID_RANGE         = 0x11,
    XQC_MOQT_REQUEST_MALFORMED_TRACK       = 0x12,
    XQC_MOQT_REQUEST_UNINTERESTED          = 0x20,
    XQC_MOQT_REQUEST_PREFIX_OVERLAP        = 0x30,
    XQC_MOQT_REQUEST_NAMESPACE_TOO_LARGE   = 0x31,
    XQC_MOQT_REQUEST_UNSUPPORTED_EXTENSION = 0x33,
    XQC_MOQT_REQUEST_REDIRECT              = 0x34,
    XQC_MOQT_REQUEST_CONFLICTING_FILTERS   = 0x35,
    XQC_MOQT_REQUEST_INVALID_FILTER        = 0x36,
} xqc_moqt_request_error_t;

typedef enum {
    XQC_MOQT_PUBLISH_INTERNAL_ERROR  = 0x00,
    XQC_MOQT_PUBLISH_UNAUTHORIZED    = 0x01,
    XQC_MOQT_PUBLISH_TRACK_ENDED     = 0x02,
    XQC_MOQT_PUBLISH_GOING_AWAY      = 0x04,
    XQC_MOQT_PUBLISH_TOO_FAR_BEHIND  = 0x05,
    XQC_MOQT_PUBLISH_EXPIRED         = 0x06,
    XQC_MOQT_PUBLISH_UPDATE_FAILED   = 0x08,
    XQC_MOQT_PUBLISH_EXCESSIVE_LOAD  = 0x09,
    XQC_MOQT_PUBLISH_MALFORMED_TRACK = 0x12,
} xqc_moqt_publish_done_code_t;

typedef enum {
    XQC_MOQT_RESET_INTERNAL_ERROR        = 0x00,
    XQC_MOQT_RESET_CANCELLED             = 0x01,
    XQC_MOQT_RESET_DELIVERY_TIMEOUT      = 0x02,
    XQC_MOQT_RESET_SESSION_CLOSED        = 0x03,
    XQC_MOQT_RESET_GOING_AWAY            = 0x04,
    XQC_MOQT_RESET_TOO_FAR_BEHIND        = 0x05,
    XQC_MOQT_RESET_UNKNOWN_OBJECT_STATUS = 0x06,
    XQC_MOQT_RESET_EXPIRED_AUTH_TOKEN    = 0x07,
    XQC_MOQT_RESET_EXCESSIVE_LOAD        = 0x09,
    XQC_MOQT_RESET_MALFORMED_TRACK       = 0x12,
} xqc_moqt_reset_error_t;

struct xqc_moqt_kv_s {
    uint64_t        type;
    union {
        uint64_t        integer;
        struct iovec    bytes;
    } value;
};

#define XQC_MOQT_MAX_OPTIONS 64
#define XQC_MOQT_GOAWAY_MAX_URI 8192

typedef enum {
    XQC_MOQT_OPT_PATH                 = 0x01,
    XQC_MOQT_OPT_AUTHORIZATION_TOKEN  = 0x03,
    XQC_MOQT_OPT_MAX_AUTH_TOKEN_CACHE = 0x04,
    XQC_MOQT_OPT_AUTHORITY            = 0x05,
    XQC_MOQT_OPT_MAX_FILTER_RANGES    = 0x06,
    XQC_MOQT_OPT_IMPLEMENTATION       = 0x07,
    XQC_MOQT_OPT_MAX_REQUEST_UPDATES  = 0x08,
} xqc_moqt_setup_option_t;

typedef enum {
    XQC_MOQT_NO_ERROR                   = 0x00,
    XQC_MOQT_INTERNAL_ERROR             = 0x01,
    XQC_MOQT_UNAUTHORIZED               = 0x02,
    XQC_MOQT_PROTOCOL_VIOLATION         = 0x03,
    XQC_MOQT_INVALID_REQUEST_ID         = 0x04,
    XQC_MOQT_DUPLICATE_TRACK_ALIAS      = 0x05,
    XQC_MOQT_KEY_VALUE_FORMATTING_ERROR = 0x06,
    XQC_MOQT_INVALID_PATH               = 0x08,
    XQC_MOQT_MALFORMED_PATH             = 0x09,
    XQC_MOQT_CONTROL_MESSAGE_TIMEOUT    = 0x11,
    XQC_MOQT_AUTH_TOKEN_CACHE_OVERFLOW  = 0x13,
    XQC_MOQT_MALFORMED_AUTH_TOKEN       = 0x16,
    XQC_MOQT_UNKNOWN_AUTH_TOKEN_ALIAS   = 0x17,
    XQC_MOQT_INVALID_AUTHORITY          = 0x19,
    XQC_MOQT_MALFORMED_AUTHORITY        = 0x1a,
    XQC_MOQT_TOO_MANY_REQUEST_UPDATES   = 0x1b,
} xqc_moqt_session_error_t;

typedef struct {
    uint64_t    max_auth_token_cache;
    uint64_t    max_filter_ranges;
    uint64_t    max_request_updates;
} xqc_moqt_receive_limits_t;

typedef struct {
    uint64_t        type;
    struct iovec    value;
} xqc_moqt_token_t;

/* Borrowed during on_setup; REGISTER is resolved as USE_VALUE (zero cache). */
typedef struct {
    const xqc_moqt_kv_t        *options;
    size_t                      option_count;
    const xqc_moqt_token_t     *tokens;
    size_t                      token_count;
    xqc_moqt_receive_limits_t   limits;
} xqc_moqt_setup_t;

typedef struct {
    /* Required policy: zero accepts, otherwise a session error code. */
    uint64_t    (*on_setup)(xqc_moqt_session_t *session,
        const xqc_moqt_setup_t *setup, void *user_data);
    void        (*on_ready)(xqc_moqt_session_t *session, void *user_data);
    void        (*on_goaway)(xqc_moqt_session_t *session,
        const struct iovec *uri, uint64_t timeout_ms, void *user_data);
    void        (*on_closed)(xqc_moqt_session_t *session, uint64_t error,
        void *user_data);
    /* XQC_OK permits; XQC_ERROR rejects with *error. Missing policy denies. */
    xqc_int_t   (*on_authorize)(xqc_moqt_request_t *request,
        const xqc_moqt_message_t *message,
        const xqc_moqt_message_t *candidate, uint64_t *error, void *user_data);
    void        (*on_message)(xqc_moqt_request_t *request,
        const xqc_moqt_message_t *message, void *user_data);
    /* NULL error means graceful closure; the handle expires on return. */
    void        (*on_request_closed)(xqc_moqt_request_t *request,
        const xqc_moqt_error_t *error, void *user_data);
    /* Delivery is finished; independent of request closure, handle expires. */
    void        (*on_subscription_closed)(xqc_moqt_subscription_t *subscription,
        const xqc_moqt_error_t *error, void *user_data);
    /* subscription is non-NULL for Fill; independent FETCH passes NULL. */
    void        (*on_fetch_ready)(xqc_moqt_fetch_t *fetch,
        xqc_moqt_subscription_t *subscription, void *user_data);
    /* NULL error means complete FIN; the handle expires on return. */
    void        (*on_fetch_closed)(xqc_moqt_fetch_t *fetch,
        const xqc_moqt_error_t *error, void *user_data);
    /* Object bytes expire on return; stream == NULL for a Datagram. */
    void        (*on_object)(xqc_moqt_subscription_t *subscription,
        xqc_moqt_stream_t *stream, const xqc_moqt_object_t *object,
        void *user_data);
    /* Last metadata has no borrowed bytes; NULL error means complete FIN. */
    void        (*on_stream_closed)(xqc_moqt_stream_t *stream,
        const xqc_moqt_object_t *last, const xqc_moqt_error_t *error,
        void *user_data);
    /* Retry the blocked data stream, or Datagram when stream == NULL. */
    void        (*on_writable)(xqc_moqt_session_t *session,
        xqc_moqt_stream_t *stream, void *user_data);
    /*
     * SUBSCRIBE_NAMESPACE changes, with a borrowed complete binary name.
     * Duplicate adds are suppressed; response FIN/reset/cancel removes all.
     * on_message still receives the original wire suffix, not these removals.
     */
    void        (*on_namespace)(xqc_moqt_request_t *request,
        const xqc_moqt_namespace_t *name, xqc_bool_t available,
        void *user_data);
    /* Borrowed complete name; on_message also receives the wire suffix. */
    void        (*on_publish_skipped)(xqc_moqt_request_t *request,
        const xqc_moqt_namespace_t *name, const struct iovec *track_name,
        void *user_data);
} xqc_moqt_callbacks_t;

/*
 * Create in conn_create_notify, start in conn_handshake_finished, destroy in
 * conn_close_notify. Config, callbacks and SETUP bytes are copied. The session
 * owns protocol/datagram user data; transport user data remains application-
 * owned. Callbacks may close/send, but must not destroy the session.
 */
XQC_EXPORT_PUBLIC_API
xqc_moqt_session_t *xqc_moqt_session_create(xqc_connection_t *conn,
    const xqc_moqt_config_t *config, const xqc_moqt_callbacks_t *callbacks,
    void *user_data);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_session_start(xqc_moqt_session_t *session);

/* Copies and queues the frame; writable callbacks resume partial I/O. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_session_goaway(xqc_moqt_session_t *session,
    const struct iovec *uri, uint64_t timeout_ms);

XQC_EXPORT_PUBLIC_API
void xqc_moqt_session_close(xqc_moqt_session_t *session, uint64_t error);

XQC_EXPORT_PUBLIC_API
void xqc_moqt_session_destroy(xqc_moqt_session_t *session);

/* IDs are assigned by the session; all outgoing bytes are copied. */
XQC_EXPORT_PUBLIC_API
xqc_moqt_request_t *xqc_moqt_request_open(xqc_moqt_session_t *session,
    const xqc_moqt_message_t *message);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_request_send(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *message);

/*
 * Enumerate authorized tracks on an accepted incoming SUBSCRIBE_TRACKS.
 * publication_id is stable for one publication, unique for new publications
 * of the same full name, and must not be reused during this request's life.
 * publish contains a full name and PUBLISH metadata. Bytes are copied.
 * XQC_OK with *publication != NULL creates an independent PUBLISH request.
 * XQC_OK with NULL means excluded, already offered, or PUBLISH_SKIPPED sent.
 * Stream exhaustion sends SKIPPED; inability to retain/notify it cancels St.
 * Cancel/FIN of St does not cancel Pc. The caller stops enumeration before
 * on_request_closed returns; expired request handles must never be reused.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_request_publish(xqc_moqt_request_t *request,
    uint64_t publication_id, const xqc_moqt_message_t *publish,
    xqc_moqt_request_t **publication);

/* Same enumeration contract, explicitly skip an unavailable publication. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_request_skip(xqc_moqt_request_t *request,
    uint64_t publication_id, const xqc_moqt_message_t *publish);

/* FIN closes only the sending direction; cancel closes open directions. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_request_finish(xqc_moqt_request_t *request);

XQC_EXPORT_PUBLIC_API
void xqc_moqt_request_cancel(xqc_moqt_request_t *request, uint64_t error);

XQC_EXPORT_PUBLIC_API
uint64_t xqc_moqt_request_id(const xqc_moqt_request_t *request);

/* Delivery handle survives its request; valid until on_subscription_closed. */
XQC_EXPORT_PUBLIC_API
xqc_moqt_subscription_t *xqc_moqt_request_subscription(
    const xqc_moqt_request_t *request);

/* Cancels delivery even after its request stream has closed. */
XQC_EXPORT_PUBLIC_API
void xqc_moqt_subscription_cancel(xqc_moqt_subscription_t *subscription,
    uint64_t error);

/* FETCH delivery survives request closure; views expire on_fetch_closed. */
XQC_EXPORT_PUBLIC_API
xqc_moqt_fetch_t *xqc_moqt_request_fetch(const xqc_moqt_request_t *request);

XQC_EXPORT_PUBLIC_API
const xqc_moqt_fetch_info_t *xqc_moqt_fetch_info(const xqc_moqt_fetch_t *fetch);

/* Publisher opens exactly one data stream after sending FETCH_OK. */
XQC_EXPORT_PUBLIC_API
xqc_moqt_stream_t *xqc_moqt_fetch_open(xqc_moqt_fetch_t *fetch);

XQC_EXPORT_PUBLIC_API
xqc_moqt_fetch_t *xqc_moqt_stream_fetch(const xqc_moqt_stream_t *stream);

XQC_EXPORT_PUBLIC_API
void xqc_moqt_fetch_cancel(xqc_moqt_fetch_t *fetch, uint64_t error);

/*
 * Complete Datagram only. XQC_OK submits one object; errors retain no bytes
 * and do not advance object state. Filtered/stopped sends return -XQC_EPARAM,
 * oversize sends -XQC_EDGRAM_TOO_LARGE, blocked sends -XQC_EAGAIN,
 * expired sends -XQC_EEXPIRED.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_datagram_send(xqc_moqt_subscription_t *subscription,
    const xqc_moqt_object_t *object);

/* Explicit IDs/priority; flags select FIRST_OBJECT and END_OF_GROUP. */
XQC_EXPORT_PUBLIC_API
xqc_moqt_stream_t *xqc_moqt_subgroup_open(
    xqc_moqt_subscription_t *subscription, uint64_t group_id,
    uint64_t subgroup_id, uint8_t priority, xqc_bool_t first_in_subgroup,
    xqc_bool_t end_of_group);

/*
 * Copies a payload fragment. Continuations match metadata/offset and omit
 * properties. AGAIN retains nothing; retry after on_writable. FIN requires
 * a complete object boundary. on_stream_closed expires the stream handle.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_stream_send_object(xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *object);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_stream_finish(xqc_moqt_stream_t *stream);

XQC_EXPORT_PUBLIC_API
void xqc_moqt_stream_cancel(xqc_moqt_stream_t *stream, uint64_t error);

/* Context is the initial request type, or REQUEST_UPDATE for its response. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_message_encode(const xqc_moqt_message_t *message,
    uint64_t context, uint8_t *buf, size_t cap);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_message_decode(const uint8_t *buf, size_t len,
    uint64_t context, xqc_moqt_message_t *message);

/* Retry 0 returns -XQC_EPARAM; overflow returns -XQC_ELIMIT. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moqt_retry_deadline(uint64_t interval, xqc_usec_t now,
    xqc_usec_t *deadline);

#ifdef __cplusplus
}
#endif

#endif /* _XQC_MOQT_H_INCLUDED_ */
