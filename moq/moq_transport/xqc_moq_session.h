#ifndef _XQC_MOQ_SESSION_H_INCLUDED_
#define _XQC_MOQ_SESSION_H_INCLUDED_

#include "src/common/xqc_list.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_timer.h"
#include "moq/xqc_moq.h"
#include "moq/moq_media/xqc_moq_datachannel.h"
#include "moq/moq_transport/xqc_moq_bitrate_allocator.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/version/xqc_moq_version.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_auth.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_request.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_setup.h"

//TODO: remove this
//#define XQC_MOQ_DEBUG
#ifdef XQC_MOQ_DEBUG
#define DEBUG_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINTF(fmt, ...)
#endif

typedef enum {
    XQC_MOQ_PROFILE_ALPN_SELECTED,
    XQC_MOQ_PROFILE_ACTIVE,
    XQC_MOQ_PROFILE_FAILED,
} xqc_moq_profile_state_t;

typedef struct xqc_moq_pending_ns_request_s {
    xqc_list_head_t             list_member;
    uint64_t                    request_id;
    xqc_moq_track_ns_field_t   *track_namespace_tuple;
    uint64_t                    track_namespace_num;
} xqc_moq_pending_ns_request_t;

typedef struct {
    uint64_t                        token_type;
    uint8_t                         *token_value;
    size_t                          token_value_len;
} xqc_moq_d18_resolved_auth_token_t;

typedef enum {
    XQC_MOQ_D18_REQUEST_AUTH_OK,
    XQC_MOQ_D18_REQUEST_AUTH_SESSION_ERROR,
    XQC_MOQ_D18_REQUEST_AUTH_REQUEST_ERROR,
} xqc_moq_d18_request_auth_kind_t;

typedef struct {
    xqc_moq_d18_request_auth_kind_t kind;
    uint64_t                        error_code;
} xqc_moq_d18_request_auth_result_t;

typedef struct xqc_moq_session_s {
    uint32_t                        version;
    uint64_t                        negotiated_version;
    const xqc_moq_alpn_policy_t     *alpn_policy;
    const xqc_moq_version_profile_t *profile;
    xqc_moq_profile_state_t         profile_state;
    xqc_moq_user_session_t          *user_session;
    xqc_engine_t                    *engine;
    xqc_log_t                       *log;
    xqc_moq_role_t                  role;
    xqc_moq_role_t                  peer_role;
    xqc_moq_transport_type_t        transport_type;
    void                            *trans_conn; /* Depend on transport type */
    xqc_connection_t                *quic_conn;
    xqc_timer_manager_t             *timer_manager;
    uint8_t                         session_setup_done;
    xqc_moq_stream_t                *ctl_stream;
    xqc_moq_stream_t                *peer_ctl_stream;
    xqc_moq_datachannel_t           datachannel;
    xqc_moq_session_callbacks_t     session_callbacks;
    xqc_moq_on_request_cancelled_pt on_request_cancelled;
    uint32_t                        callback_depth;
    uint8_t                         destroy_pending;
    uint8_t                         destroying;
    uint64_t                        active_stream_count;
    xqc_moq_on_request_update_pt    on_request_update;
    xqc_moq_on_publish_blocked_pt   on_publish_blocked;
    xqc_moq_on_goaway_draft18_pt   on_goaway_draft18;
    xqc_list_head_t                 local_subscribe_list;
    xqc_list_head_t                 peer_subscribe_list;
    xqc_list_head_t                 track_list_for_pub;
    xqc_list_head_t                 track_list_for_sub;
    xqc_list_head_t                 peer_subscribe_namespace_list;
    xqc_list_head_t                 peer_ns_pending_inbound_list;
    xqc_list_head_t                 local_advertised_namespace_list;
    xqc_list_head_t                 peer_advertised_namespace_list;
    xqc_list_head_t                 local_request_stream_list;
    xqc_list_head_t                 peer_request_stream_list;
    xqc_list_head_t                 d18_deferred_stream_list;
    size_t                          d18_deferred_stream_bytes;
    xqc_moq_d18_request_registry_t  d18_request_registry;
    xqc_moq_d18_auth_cache_t        peer_auth_cache;
    xqc_moq_d18_resolved_auth_token_t *peer_setup_auth_tokens;
    size_t                          peer_setup_auth_token_count;
    uint8_t                         *peer_setup_path;
    size_t                          peer_setup_path_len;
    uint8_t                         peer_setup_path_present;
    uint8_t                         *peer_setup_authority;
    size_t                          peer_setup_authority_len;
    uint8_t                         peer_setup_authority_present;
    uint8_t                         *peer_setup_implementation;
    size_t                          peer_setup_implementation_len;
    uint8_t                         peer_setup_implementation_present;
    uint64_t                        peer_max_auth_token_cache_size;
    uint8_t                         peer_has_max_auth_token_cache_size;
    uint64_t                        request_id_allocator;
    uint64_t                        track_alias_allocator;
    xqc_moq_bitrate_allocator_t     bitrate_allocator;
    xqc_int_t                       enable_fec;
    float                           fec_code_rate;
    xqc_int_t                       use_unified_setup;
    uint8_t                         enable_datachannel;
    /* -1 = follow the negotiated profile, 0 = off, 1 = on */
    int8_t                          enable_catalog;
    uint8_t                         goaway_sent;
    uint8_t                         goaway_received;
    uint8_t                         draining;
    uint8_t                         d18_control_goaway_sent;
    uint8_t                         d18_control_goaway_received;
    uint8_t                         d18_control_goaway_timer_registered;
    uint8_t                         d18_control_goaway_timer_fired;
    uint64_t                        d18_control_goaway_cutoff;
    uint64_t                        d18_control_goaway_timeout_ms;
    uint64_t                        d18_control_goaway_received_cutoff;
    uint64_t                        d18_control_goaway_received_timeout_ms;
    xqc_gp_timer_id_t               d18_control_goaway_timer_id;
    uint8_t                         peer_ns_request_id_seen;
    uint64_t                        max_peer_ns_request_id;
    uint8_t                         peer_request_id_seen;
    uint64_t                        max_peer_request_id;
    xqc_list_head_t                 local_ns_pending_list;
    char                            *goaway_new_session_uri;
    size_t                          goaway_new_session_uri_len;
} xqc_moq_session_t;

xqc_bool_t xqc_moq_session_catalog_enabled(
    const xqc_moq_session_t *session);

xqc_int_t xqc_moq_session_bind_policy(xqc_moq_session_t *session,
    const xqc_moq_alpn_policy_t *policy);

xqc_int_t xqc_moq_session_bind_connection_alpn(
    xqc_moq_session_t *session);

xqc_int_t xqc_moq_session_validate_setup_type(
    xqc_moq_session_t *session, uint64_t setup_type);

xqc_int_t xqc_moq_session_negotiate_version(xqc_moq_session_t *session,
    const uint64_t *offered_versions, uint64_t offered_versions_num);

xqc_int_t xqc_moq_session_require_active(const xqc_moq_session_t *session);

xqc_int_t xqc_moq_session_negotiate_version(xqc_moq_session_t *session,
    const uint64_t *offered_versions, uint64_t offered_versions_num);

typedef enum {
    MOQ_NO_ERROR                    =   0x0,
    MOQ_INTERNAL_ERROR              =   0x1,
    MOQ_UNAUTHORIZED                =   0x2,
    MOQ_PROTOCOL_VIOLATION          =   0x3,
    MOQ_DUPLICATE_TRACK_ALIAS       =   0x4,
    MOQ_PARAMETER_LENGTH_MISMATCH   =   0x5,
    MOQ_GOAWAY_TIMEOUT              =   0x10,
} xqc_moq_err_code_t;

void xqc_moq_session_on_setup(xqc_moq_session_t *session, char *extdata,
    const xqc_moq_message_parameter_t *params, uint64_t params_num);

xqc_connection_t *xqc_moq_session_quic_conn(xqc_moq_session_t *session);

void xqc_moq_session_error(xqc_moq_session_t *session, uint64_t code,
    const char *msg);

uint64_t xqc_moq_session_alloc_request_id(xqc_moq_session_t *session);

xqc_moq_d18_request_id_result_t
xqc_moq_session_register_local_request_id(xqc_moq_session_t *session,
    uint64_t request_id);

xqc_moq_d18_request_id_result_t
xqc_moq_session_register_peer_request_id(xqc_moq_session_t *session,
    uint64_t request_id);

uint64_t xqc_moq_session_auth_result_error(
    xqc_moq_d18_auth_result_t result);

uint64_t xqc_moq_session_process_peer_setup_auth(
    xqc_moq_session_t *session,
    const xqc_moq_d18_setup_options_t *options,
    uint8_t receiver_is_server);

xqc_moq_d18_request_auth_result_t
xqc_moq_session_classify_request_auth_result(
    xqc_moq_d18_auth_result_t auth_result);

xqc_moq_d18_request_auth_result_t
xqc_moq_session_process_peer_request_auth(
    xqc_moq_session_t *session,
    const xqc_moq_message_parameter_t *params, size_t params_num,
    xqc_moq_request_auth_t *request_auth);

void xqc_moq_request_auth_destroy(xqc_moq_request_auth_t *request_auth);

void xqc_moq_session_clear_peer_setup_auth_tokens(
    xqc_moq_session_t *session);

xqc_int_t xqc_moq_session_encode_draft18_setup_config(
    const xqc_moq_draft18_setup_config_t *config,
    xqc_moq_d18_setup_sender_t sender,
    xqc_moq_d18_setup_transport_t transport,
    uint8_t **encoded, size_t *encoded_len);

xqc_int_t xqc_moq_session_store_peer_setup_options(
    xqc_moq_session_t *session,
    const xqc_moq_d18_setup_options_t *options);

void xqc_moq_session_clear_peer_setup_options(xqc_moq_session_t *session);

uint64_t xqc_moq_session_alloc_subscribe_id(xqc_moq_session_t *session);

xqc_moq_subscribe_t *xqc_moq_find_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id, xqc_int_t is_local);

uint64_t xqc_moq_session_alloc_track_alias(xqc_moq_session_t *session);

xqc_moq_track_t *xqc_moq_find_track_by_alias(xqc_moq_session_t *session,
    uint64_t track_alias, xqc_moq_track_role_t role);

xqc_moq_track_t *xqc_moq_find_track_by_name(xqc_moq_session_t *session,
    const char *track_namespace, const char *track_name, xqc_moq_track_role_t role);

xqc_moq_track_t *xqc_moq_find_track_by_subscribe_id(xqc_moq_session_t *session,
    uint64_t subscribe_id, xqc_moq_track_role_t role);

void xqc_moq_session_drain(xqc_moq_session_t *session);

void xqc_moq_session_check_drain_complete(xqc_moq_session_t *session);

void xqc_moq_session_callback_enter(xqc_moq_session_t *session);

void xqc_moq_session_callback_leave(xqc_moq_session_t *session);

void xqc_moq_session_destroy_if_pending(xqc_moq_session_t *session);

xqc_int_t xqc_moq_session_admit_local_initial_request(
    const xqc_moq_session_t *session);

xqc_int_t xqc_moq_session_admit_peer_initial_request(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    uint64_t request_id);

xqc_int_t xqc_moq_session_admit_peer_request_update(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    uint64_t request_id);

void xqc_moq_session_unregister_goaway_timer(
    xqc_moq_session_t *session);

xqc_int_t xqc_moq_session_is_server(xqc_moq_session_t *session);

xqc_int_t xqc_moq_session_namespace_prefix_overlaps(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num);

xqc_int_t xqc_moq_session_find_request_id(xqc_moq_session_t *session, uint64_t request_id);

xqc_int_t xqc_moq_session_add_namespace_prefix(xqc_moq_session_t *session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num);

xqc_int_t xqc_moq_session_remove_namespace_prefix(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num);

xqc_int_t xqc_moq_session_add_pending_ns_request(xqc_moq_session_t *session, uint64_t request_id,
    const xqc_moq_track_ns_field_t *ns_tuple, uint64_t ns_num);

xqc_moq_pending_ns_request_t *xqc_moq_session_consume_pending_ns_request(xqc_moq_session_t *session, uint64_t request_id);

xqc_moq_track_t *xqc_moq_find_track_by_ns_tuple(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *ns_tuple, uint64_t ns_num,
    const char *track_name, xqc_moq_track_role_t role);

xqc_int_t xqc_moq_session_add_pending_inbound_ns(xqc_moq_session_t *session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num);

xqc_int_t xqc_moq_session_accept_pending_inbound_ns(xqc_moq_session_t *session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t **namespace_prefix_tuple, uint64_t *namespace_prefix_num);

void xqc_moq_session_reject_pending_inbound_ns(xqc_moq_session_t *session,
    uint64_t request_id);

xqc_moq_namespace_advertisement_t *xqc_moq_session_find_advertised_namespace(
    xqc_moq_session_t *session, xqc_int_t is_local,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num);

xqc_int_t xqc_moq_session_add_advertised_namespace(xqc_moq_session_t *session,
    xqc_int_t is_local, const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num);

xqc_int_t xqc_moq_session_remove_advertised_namespace(xqc_moq_session_t *session,
    xqc_int_t is_local, const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num);

xqc_int_t xqc_moq_session_bind_advertised_namespace_request(xqc_moq_session_t *session,
    xqc_int_t is_local, const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num, uint64_t request_id);

xqc_moq_namespace_advertisement_t *xqc_moq_session_find_advertised_namespace_by_request(
    xqc_moq_session_t *session, xqc_int_t is_local, uint64_t request_id);

xqc_int_t xqc_moq_session_has_active_publish_in_namespace(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num);

xqc_int_t xqc_moq_session_forward_publish_blocked(
    xqc_moq_session_t *session, const xqc_moq_stream_t *origin,
    const xqc_moq_track_ns_field_t *full_namespace,
    uint64_t full_namespace_num, const char *track_name,
    size_t track_name_len);

#endif /* _XQC_MOQ_SESSION_H_INCLUDED_ */
