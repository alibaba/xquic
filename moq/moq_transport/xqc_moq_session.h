#ifndef _XQC_MOQ_SESSION_H_INCLUDED_
#define _XQC_MOQ_SESSION_H_INCLUDED_

#include "src/common/xqc_list.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_timer.h"
#include "moq/xqc_moq.h"
#include "moq/moq_media/xqc_moq_datachannel.h"
#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "src/transport/xqc_stream.h"
#include "src/common/xqc_priority_q.h"
#include "moq/moq_transport/xqc_moq_bitrate_allocator.h"
#include "xquic/xquic_typedef.h"

//TODO: remove this
//#define XQC_MOQ_DEBUG
#ifdef XQC_MOQ_DEBUG
#define DEBUG_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINTF(fmt, ...)
#endif

#define XQC_MOQ_VERSION_LIST_SIZE   2
#define XQC_MOQ_VERSION_DRAFT_05            0xff000005
// #define XQC_MOQ_VERSION_DRAFT_07            0xff000007
#define XQC_MOQ_VERSION_DRAFT_08            0xff000008
#define XQC_MOQ_VERSION_DRAFT_8_INTEROP     0xff000088 // internal MOQ version for interop and test
#define XQC_MOQ_VERSION_DRAFT_10            0xff00000A
#define XQC_MOQ_VERSION_DRAFT_11            0xff00000B
#define XQC_MOQ_VERSION_DRAFT_13            0xff00000D
#define XQC_MOQ_VERSION_DRAFT_14            0xff00000E
// #define XQC_MOQ_CUR_VERSION                 XQC_MOQ_VERSION_DRAFT_14

#ifdef XQC_MOQ_VERSION_11
#define XQC_MOQ_CUR_VERSION                 XQC_MOQ_VERSION_DRAFT_14
#else
#define XQC_MOQ_CUR_VERSION                 XQC_MOQ_VERSION_DRAFT_05
#endif


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
    xqc_moq_datachannel_t           datachannel;
    xqc_moq_session_callbacks_t     session_callbacks;
    xqc_list_head_t                 local_subscribe_list;
    xqc_list_head_t                 peer_subscribe_list;
    xqc_list_head_t                 track_list_for_pub;
    xqc_list_head_t                 track_list_for_sub;
    uint64_t                        subscribe_id_allocator;
    uint64_t                        track_alias_allocator;
    xqc_moq_bitrate_allocator_t     bitrate_allocator;
    xqc_int_t                       enable_fec;
    float                           fec_code_rate;
    uint64_t                        max_request_id; // name changed for draft-11, former name is max_subscribe_id
    uint64_t                        moq_selected_version;
    uint64_t                        max_auth_token_cache_size;
    /* namespace subscription watches */
    xqc_list_head_t                 namespace_watch_list;
    /* Priority feature flags */
    xqc_int_t                       priority_enabled;   /* 0: off (default); 1: on */
    xqc_int_t                       priority_enforce;   /* 0: log-only; 1: enforce mapping */
} xqc_moq_session_t;


// https://www.ietf.org/archive/id/draft-ietf-moq-transport-12.html#name-termination
/*
0x0	No Error  
0x1	Internal Error  
0x2	Unauthorized  
0x3	Protocol Violation  
0x4	Invalid Request ID  
0x5	Duplicate Track Alias  
0x6	Key-Value Formatting Error
0x7	Too Many Requests  
0x8	Invalid Path  
0x9	Malformed Path  
0x10	GOAWAY Timeout  GOAWAY 
0x11	Control Message Timeout  
0x12	Data Stream Timeout  
0x13	Auth Token Cache Overflow
0x14	Duplicate Auth Token Alias
0x15	Version Negotiation Failed 
0x16	Malformed Auth Token  
0x17	Unknown Auth Token Alias
0x18	Expired Auth Token  

*/

typedef enum {
    MOQ_NO_ERROR                    =   0x0,
    MOQ_INTERNAL_ERROR              =   0x1,
    MOQ_UNAUTHORIZED                =   0x2,
    MOQ_PROTOCOL_VIOLATION          =   0x3,
    MOQ_DUPLICATE_TRACK_ALIAS       =   0x4,
    MOQ_PARAMETER_LENGTH_MISMATCH   =   0x5,
    MOQ_KEY_VALUE_FORMATTING_ERROR  =   0x6,
    MOQ_TOO_MANY_REQUESTS           =   0x7,
    MOQ_INVALID_PATH                =   0x8,
    MOQ_MALFORMED_PATH              =   0x9,
    MOQ_GOAWAY_TIMEOUT              =   0x10,
    MOQ_CONTROL_MESSAGE_TIMEOUT     =   0x11,
    MOQ_DATA_STREAM_TIMEOUT         =   0x12,
    MOQ_AUTH_TOKEN_CACHE_OVERFLOW   =   0x13,
    MOQ_DUPLICATE_AUTH_TOKEN_ALIAS  =   0x14,
    MOQ_VERSION_NEGOTIATION_FAILED  =   0x15,
    MOQ_MALFORMED_AUTH_TOKEN        =   0x16,
    MOQ_UNKNOWN_AUTH_TOKEN_ALIAS    =   0x17,
    MOQ_EXPIRED_AUTH_TOKEN          =   0x18,
} xqc_moq_err_code_t_v12;

typedef xqc_moq_err_code_t_v12 xqc_moq_err_code_t;
// typedef enum {
//     MOQ_NO_ERROR                    =   0x0,
//     MOQ_INTERNAL_ERROR              =   0x1,
//     MOQ_UNAUTHORIZED                =   0x2,
//     MOQ_PROTOCOL_VIOLATION          =   0x3,
//     MOQ_DUPLICATE_TRACK_ALIAS       =   0x4,
//     MOQ_PARAMETER_LENGTH_MISMATCH   =   0x5,
//     MOQ_GOAWAY_TIMEOUT              =   0x10,
// } xqc_moq_err_code_t_v05;

void xqc_moq_session_on_setup(xqc_moq_session_t *session, char *extdata);

xqc_connection_t *xqc_moq_session_quic_conn(xqc_moq_session_t *session);

void xqc_moq_session_error(xqc_moq_session_t *session, xqc_moq_err_code_t code, const char *msg);

uint64_t xqc_moq_session_alloc_subscribe_id(xqc_moq_session_t *session);

xqc_moq_subscribe_t *xqc_moq_find_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id, xqc_int_t is_local);

uint64_t xqc_moq_session_alloc_track_alias(xqc_moq_session_t *session);

xqc_moq_track_t *xqc_moq_find_track_by_alias(xqc_moq_session_t *session,
    uint64_t track_alias, xqc_moq_track_role_t role); // Due to moq_subscribe track_alias is deprecated, use find_track_by_subscribe_id instead

xqc_moq_track_t *xqc_moq_find_track_by_name(xqc_moq_session_t *session,
    const char *track_namespace, const char *track_name, xqc_moq_track_role_t role);

xqc_moq_track_t *xqc_moq_find_track_by_subscribe_id(xqc_moq_session_t *session,
     uint64_t subscribe_id, xqc_moq_track_role_t role);

/* priority feature config */
void xqc_moq_set_priority_config(xqc_moq_session_t *session, xqc_int_t enabled, xqc_int_t enforce);

#endif /* _XQC_MOQ_SESSION_H_INCLUDED_ */
