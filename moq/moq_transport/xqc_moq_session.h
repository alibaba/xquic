#ifndef _XQC_MOQ_SESSION_H_INCLUDED_
#define _XQC_MOQ_SESSION_H_INCLUDED_

#include "src/common/xqc_list.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_timer.h"
#include "moq/xqc_moq.h"
#include "moq/moq_media/xqc_moq_datachannel.h"
#include "moq/moq_transport/xqc_moq_bitrate_allocator.h"

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
    xqc_int_t                       use_client_setup_v14;
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

void xqc_moq_session_on_setup(xqc_moq_session_t *session, char *extdata);

xqc_connection_t *xqc_moq_session_quic_conn(xqc_moq_session_t *session);

void xqc_moq_session_error(xqc_moq_session_t *session, xqc_moq_err_code_t code, const char *msg);

uint64_t xqc_moq_session_alloc_subscribe_id(xqc_moq_session_t *session);

xqc_moq_subscribe_t *xqc_moq_find_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id, xqc_int_t is_local);

uint64_t xqc_moq_session_alloc_track_alias(xqc_moq_session_t *session);

xqc_moq_track_t *xqc_moq_find_track_by_alias(xqc_moq_session_t *session,
    uint64_t track_alias, xqc_moq_track_role_t role);

xqc_moq_track_t *xqc_moq_find_track_by_name(xqc_moq_session_t *session,
    const char *track_namespace, const char *track_name, xqc_moq_track_role_t role);

#endif /* _XQC_MOQ_SESSION_H_INCLUDED_ */
