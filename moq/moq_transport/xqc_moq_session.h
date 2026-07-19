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

//TODO: remove this
//#define XQC_MOQ_DEBUG
#ifdef XQC_MOQ_DEBUG
#define DEBUG_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINTF(fmt, ...)
#endif

//#define XQC_MOQ_VERSION 0x00000001
#define XQC_MOQ_VERSION_5 0xff000005
#define XQC_MOQ_VERSION_14 0xff00000E
#define XQC_MOQ_VERSION_18 0xff000012

typedef struct xqc_moq_pending_ns_request_s {
    xqc_list_head_t             list_member;
    uint64_t                    request_id;
    xqc_moq_track_ns_field_t   *track_namespace_tuple;
    uint64_t                    track_namespace_num;
} xqc_moq_pending_ns_request_t;

typedef struct xqc_moq_session_s {
    uint32_t                        version;
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
    xqc_list_head_t                 local_subscribe_list;
    xqc_list_head_t                 peer_subscribe_list;
    xqc_list_head_t                 track_list_for_pub;
    xqc_list_head_t                 track_list_for_sub;
    xqc_list_head_t                 peer_subscribe_namespace_list;
    xqc_list_head_t                 peer_ns_pending_inbound_list;
    xqc_list_head_t                 local_advertised_namespace_list;
    xqc_list_head_t                 peer_advertised_namespace_list;
    uint64_t                        request_id_allocator;
    uint64_t                        track_alias_allocator;
    xqc_moq_bitrate_allocator_t     bitrate_allocator;
    xqc_int_t                       enable_fec;
    float                           fec_code_rate;
    xqc_int_t                       use_client_setup_v14;
    xqc_int_t                       use_setup_v18;
    uint8_t                         enable_datachannel;
    uint8_t                         enable_catalog;
    uint8_t                         goaway_sent;
    uint8_t                         goaway_received;
    uint8_t                         draining;
    uint8_t                         peer_ns_request_id_seen;
    uint64_t                        max_peer_ns_request_id;
    xqc_list_head_t                 local_ns_pending_list;
    char                            *goaway_new_session_uri;
    size_t                          goaway_new_session_uri_len;
} xqc_moq_session_t;

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

void xqc_moq_session_error(xqc_moq_session_t *session, xqc_moq_err_code_t code, const char *msg);

uint64_t xqc_moq_session_alloc_request_id(xqc_moq_session_t *session);

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

xqc_int_t xqc_moq_session_has_active_publish_in_namespace(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num);

#endif /* _XQC_MOQ_SESSION_H_INCLUDED_ */
