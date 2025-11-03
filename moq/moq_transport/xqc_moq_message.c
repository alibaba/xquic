#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/xqc_moq.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_log.h"
#include "xquic/xquic_typedef.h"
#include <stdint.h>

static xqc_moq_msg_ctl_stream_func_map_t moq_msg_func_map[] = {
    {XQC_MOQ_MSG_SUBSCRIBE_UPDATE,     xqc_moq_msg_create_subscribe_update_v05, xqc_moq_msg_free_subscribe_update_v05},
    {XQC_MOQ_MSG_SUBSCRIBE_UPDATE,     xqc_moq_msg_create_subscribe_update_v13, xqc_moq_msg_free_subscribe_update_v13},
    {XQC_MOQ_MSG_SUBSCRIBE,            xqc_moq_msg_create_subscribe_v13,    xqc_moq_msg_free_subscribe_v13},
    {XQC_MOQ_MSG_SUBSCRIBE_OK,         xqc_moq_msg_create_subscribe_ok,     xqc_moq_msg_free_subscribe_ok    },
    {XQC_MOQ_MSG_SUBSCRIBE_ERROR,      xqc_moq_msg_create_subscribe_error,  xqc_moq_msg_free_subscribe_error },
    {XQC_MOQ_MSG_SUBSCRIBE_DONE,       xqc_moq_msg_create_subscribe_done,   xqc_moq_msg_free_subscribe_done  },
    {XQC_MOQ_MSG_ANNOUNCE,             xqc_moq_msg_create_announce,         xqc_moq_msg_free_announce      },
    {XQC_MOQ_MSG_ANNOUNCE_OK,          xqc_moq_msg_create_announce_ok,      xqc_moq_msg_free_announce_ok      }, 
    {XQC_MOQ_MSG_ANNOUNCE_ERROR,       xqc_moq_msg_create_announce_error,      xqc_moq_msg_free_announce_error      },
    // {XQC_MOQ_MSG_UNANNOUNCE,           xqc_moq_msg_create_unannounce,         xqc_moq_msg_free_unannounce      },
    {XQC_MOQ_MSG_UNSUBSCRIBE,           xqc_moq_msg_create_unsubscribe,         xqc_moq_msg_free_unsubscribe      },
    // {XQC_MOQ_MSG_SUBSCRIBE_DONE,       xqc_moq_msg_create_subscribe_done,    xqc_moq_msg_free_subscribe_done   },
//    {XQC_MOQ_MSG_ANNOUNCE_CANCEL,      xqc_moq_msg_create_announce_cancel,      xqc_moq_msg_free_announce_cancel                             },
//    {XQC_MOQ_MSG_TRACK_STATUS_REQUEST, xqc_moq_msg_create_track_status_request, xqc_moq_msg_free_track_status_request},
   {XQC_MOQ_MSG_TRACK_STATUS,         xqc_moq_msg_create_track_status,         xqc_moq_msg_free_track_status      },
   {XQC_MOQ_MSG_TRACK_STATUS_OK,     xqc_moq_msg_create_track_status_ok,   xqc_moq_msg_free_track_status_ok },
   {XQC_MOQ_MSG_TRACK_STATUS_ERROR,  xqc_moq_msg_create_track_status_error, xqc_moq_msg_free_track_status_error},
   {XQC_MOQ_MSG_GOAWAY,               xqc_moq_msg_create_goaway,               xqc_moq_msg_free_goaway          },
   {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE,  xqc_moq_msg_create_subscribe_namespace, xqc_moq_msg_free_subscribe_namespace},
   {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK, xqc_moq_msg_create_subscribe_namespace_ok, xqc_moq_msg_free_subscribe_namespace_ok},
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE, xqc_moq_msg_create_publish_namespace, xqc_moq_msg_free_publish_namespace},
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE, xqc_moq_msg_create_publish_namespace_done, xqc_moq_msg_free_publish_namespace_done},
    {XQC_MOQ_MSG_CLIENT_SETUP,         xqc_moq_msg_create_client_setup,     xqc_moq_msg_free_client_setup    },
    {XQC_MOQ_MSG_SERVER_SETUP,         xqc_moq_msg_create_server_setup,     xqc_moq_msg_free_server_setup    },
//    {XQC_MOQ_MSG_STREAM_HEADER_GROUP,  NULL,                                NULL                             },
    {XQC_MOQ_MSG_OBJECT_STREAM,        xqc_moq_msg_create_object_stream,    xqc_moq_msg_free_object_stream   },
    {XQC_MOQ_MSG_STREAM_HEADER_TRACK,  xqc_moq_msg_create_track_header,     xqc_moq_msg_free_track_header    },
   {XQC_MOQ_MSG_TRACK_STREAM_OBJECT,  xqc_moq_msg_create_track_stream_obj, xqc_moq_msg_free_track_stream_obj},
    {XQC_MOQ_MSG_MAX_REQUEST_ID,      xqc_moq_msg_create_max_request_id, xqc_moq_msg_free_max_request_id},
    {XQC_MOQ_MSG_REQUESTS_BLOCKED,    xqc_moq_msg_create_requests_blocked, xqc_moq_msg_free_requests_blocked},
//    {XQC_MOQ_MSG_GROUP_STREAM_OBJECT,  NULL,                                NULL                             },
    {XQC_MOQ_MSG_PUBLISH,             xqc_moq_msg_create_publish,           xqc_moq_msg_free_publish         },
    {XQC_MOQ_MSG_PUBLISH_OK,          xqc_moq_msg_create_publish_ok,        xqc_moq_msg_free_publish_ok      },
    {XQC_MOQ_MSG_PUBLISH_ERROR,       xqc_moq_msg_create_publish_error,     xqc_moq_msg_free_publish_error   },
};

static xqc_moq_msg_data_stream_func_map_t moq_msg_data_func_map[] = {
   {XQC_MOQ_MSG_TRACK_STREAM_OBJECT,   xqc_moq_msg_create_track_stream_obj, xqc_moq_msg_free_track_stream_obj},
    {XQC_MOQ_MSG_STREAM_HEADER_TRACK,  xqc_moq_msg_create_track_header,     xqc_moq_msg_free_track_header    },
    {XQC_MOQ_MSG_OBJECT_STREAM,        xqc_moq_msg_create_object_stream,    xqc_moq_msg_free_object_stream   },
    {XQC_MOQ_SUBGROUP,             xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_OBJECT,      xqc_moq_msg_create_subgroup_object, xqc_moq_msg_free_subgroup_object},
    {XQC_MOQ_SUBGROUP_OBJECT_EXT,  xqc_moq_msg_create_subgroup_object_ext, xqc_moq_msg_free_subgroup_object_ext},
    // Add all 12 SUBGROUP_HEADER types (0x10-0x1D)
    {XQC_MOQ_SUBGROUP_0x10,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x11,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x12,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x13,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x14,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x15,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x18,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x19,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x1A,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x1B,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x1C,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
    {XQC_MOQ_SUBGROUP_0x1D,        xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup},
};

const xqc_moq_msg_base_t client_setup_base_v11 = {
    .type       = xqc_moq_msg_client_setup_type,
    .encode_len = xqc_moq_msg_encode_client_setup_len,
    .encode     = xqc_moq_msg_encode_client_setup,
    .decode     = xqc_moq_msg_decode_client_setup,
    .on_msg     = xqc_moq_on_client_setup,
};

const xqc_moq_msg_base_t client_setup_base_v05 = {
    .type       = xqc_moq_msg_client_setup_type,
    .encode_len = xqc_moq_msg_encode_client_setup_len_v05,
    .encode     = xqc_moq_msg_encode_client_setup_v05,
    .decode     = xqc_moq_msg_decode_client_setup_v05,
    .on_msg     = xqc_moq_on_client_setup,
};

const xqc_moq_msg_base_t server_setup_base = {
    .type       = xqc_moq_msg_server_setup_type,
    .encode_len = xqc_moq_msg_encode_server_setup_len,
    .encode     = xqc_moq_msg_encode_server_setup,
    .decode     = xqc_moq_msg_decode_server_setup,
    .on_msg     = xqc_moq_on_server_setup,
};

// TODO
// const xqc_moq_msg_base_t server_setup_base_v05 = {
//     .type       = xqc_moq_msg_server_setup_type_v05,
//     .encode_len = xqc_moq_msg_encode_server_setup_len_v05,
//     .encode     = xqc_moq_msg_encode_server_setup_v05,
//     .decode     = xqc_moq_msg_decode_server_setup_v05,
//     .on_msg     = xqc_moq_on_server_setup_v05,
// };

const xqc_moq_msg_base_t subscribe_base_v13 = {
    .type       = xqc_moq_msg_subscribe_type,
    .encode_len = xqc_moq_msg_encode_subscribe_len_v13,
    .encode     = xqc_moq_msg_encode_subscribe_v13,
    .decode     = xqc_moq_msg_decode_subscribe_v13,
    .on_msg     = xqc_moq_on_subscribe_v13,
};

const xqc_moq_msg_base_t subscribe_base_v05 = {
    .type       = xqc_moq_msg_subscribe_type,
    .encode_len = xqc_moq_msg_encode_subscribe_len_v05,
    .encode     = xqc_moq_msg_encode_subscribe_v05,
    .decode     = xqc_moq_msg_decode_subscribe_v05,
    .on_msg     = xqc_moq_on_subscribe_v05,
};

const xqc_moq_msg_base_t subscribe_update_base_v05 = {
    .type       = xqc_moq_msg_subscribe_update_type,
    .encode_len = xqc_moq_msg_encode_subscribe_update_len_v05,
    .encode     = xqc_moq_msg_encode_subscribe_update_v05,
    .decode     = xqc_moq_msg_decode_subscribe_update_v05,
    .on_msg     = xqc_moq_on_subscribe_update_v05,
};

const xqc_moq_msg_base_t subscribe_update_base_v13 = {
    .type       = xqc_moq_msg_subscribe_update_type,
    .encode_len = xqc_moq_msg_encode_subscribe_update_len_v13,
    .encode     = xqc_moq_msg_encode_subscribe_update_v13,
    .decode     = xqc_moq_msg_decode_subscribe_update_v13,
    .on_msg     = xqc_moq_on_subscribe_update_v13,
};

const xqc_moq_msg_base_t subscribe_ok_base_v11 = {
    .type       = xqc_moq_msg_subscribe_ok_type,
    .encode_len = xqc_moq_msg_encode_subscribe_ok_len_v11,
    .encode     = xqc_moq_msg_encode_subscribe_ok_v11,
    .decode     = xqc_moq_msg_decode_subscribe_ok_v11,
    .on_msg     = xqc_moq_on_subscribe_ok_v13,
};

const xqc_moq_msg_base_t subscribe_ok_v05 = {
    .type       = xqc_moq_msg_subscribe_ok_type,
    .encode_len = xqc_moq_msg_encode_subscribe_ok_len_v05,
    .encode     = xqc_moq_msg_encode_subscribe_ok_v05,
    .decode     = xqc_moq_msg_decode_subscribe_ok_v05,
    .on_msg     = xqc_moq_on_subscribe_ok_v05,
};

const xqc_moq_msg_base_t subscribe_error_base = {
    .type       = xqc_moq_msg_subscribe_error_type,
    .encode_len = xqc_moq_msg_encode_subscribe_error_len,
    .encode     = xqc_moq_msg_encode_subscribe_error,
    .decode     = xqc_moq_msg_decode_subscribe_error,
    .on_msg     = xqc_moq_on_subscribe_error_v13,
};

const xqc_moq_msg_base_t object_stream_base = {
    .type       = xqc_moq_msg_object_stream_type,
    .encode_len = xqc_moq_msg_encode_object_stream_len,
    .encode     = xqc_moq_msg_encode_object_stream,
    .decode     = xqc_moq_msg_decode_object_stream,
    .on_msg     = xqc_moq_on_object_stream,
};

const xqc_moq_msg_base_t track_stream_obj_base = {
    .type       = xqc_moq_msg_track_stream_obj_type,
    .encode_len = xqc_moq_msg_encode_track_stream_obj_len,
    .encode     = xqc_moq_msg_encode_track_stream_obj,
    .decode     = xqc_moq_msg_decode_track_stream_obj,
    .on_msg     = xqc_moq_on_track_stream_obj,
};


const xqc_moq_msg_base_t track_header_base = {
    .type       = xqc_moq_msg_track_header_type,
    .encode_len = xqc_moq_msg_encode_track_header_len,
    .encode     = xqc_moq_msg_encode_track_header,
    .decode     = xqc_moq_msg_decode_track_header,
    .on_msg     = xqc_moq_on_track_header,
};

const xqc_moq_msg_base_t max_request_id_base = {
    .type       = xqc_moq_msg_max_request_id_type,
    .encode_len = xqc_moq_msg_encode_max_request_id_len,
    .encode     = xqc_moq_msg_encode_max_request_id,
    .decode     = xqc_moq_msg_decode_max_request_id,
    .on_msg     = xqc_moq_on_max_request_id,
};

const xqc_moq_msg_base_t requests_blocked_base = {
    .type       = xqc_moq_msg_requests_blocked_type,
    .encode_len = xqc_moq_msg_encode_requests_blocked_len,
    .encode     = xqc_moq_msg_encode_requests_blocked,
    .decode     = xqc_moq_msg_decode_requests_blocked,
    .on_msg     = xqc_moq_on_requests_blocked,
};

const xqc_moq_msg_base_t subgroup_base = {
    .type       = xqc_moq_msg_subgroup_type,
    .encode_len = xqc_moq_msg_encode_subgroup_len,
    .encode     = xqc_moq_msg_encode_subgroup,
    .decode     = xqc_moq_msg_decode_subgroup,
    .on_msg     = xqc_moq_on_subgroup,
};

const xqc_moq_msg_base_t subgroup_object_base = {
    .type       = xqc_moq_msg_subgroup_object_type,
    .encode_len = xqc_moq_msg_encode_subgroup_object_len,
    .encode     = xqc_moq_msg_encode_subgroup_object,
    .decode     = xqc_moq_msg_decode_subgroup_object,
    .on_msg     = xqc_moq_on_subgroup_object,
};

const xqc_moq_msg_base_t subgroup_object_ext_base = {
    .type       = xqc_moq_msg_subgroup_object_ext_type,
    .encode_len = xqc_moq_msg_encode_subgroup_object_ext_len,
    .encode     = xqc_moq_msg_encode_subgroup_object_ext,
    .decode     = xqc_moq_msg_decode_subgroup_object_ext,
    .on_msg     = xqc_moq_on_subgroup_object_ext,
};

void
xqc_moq_msg_subgroup_object_ext_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = subgroup_object_ext_base;
}

const xqc_moq_msg_base_t announce_base = {
    .type       = xqc_moq_msg_announce_type,
    .encode_len = xqc_moq_msg_encode_announce_len,
    .encode     = xqc_moq_msg_encode_announce,
    .decode     = xqc_moq_msg_decode_announce, // TODO later, current version only for server side
    .on_msg     = xqc_moq_on_announce,        // TODO later 
};

const xqc_moq_msg_base_t fetch_base = {
    .type       = xqc_moq_msg_fetch_type,
    .encode_len = xqc_moq_msg_encode_fetch_len,
    .encode     = xqc_moq_msg_encode_fetch,
    .decode     = xqc_moq_msg_decode_fetch,
    .on_msg     = xqc_moq_on_fetch,
};

const xqc_moq_msg_base_t announce_ok_base = {
    .type       = xqc_moq_msg_announce_ok_type,
    .encode_len = xqc_moq_msg_encode_announce_ok_len,
    .encode     = xqc_moq_msg_encode_announce_ok,
    .decode     = xqc_moq_msg_decode_announce_ok,
    .on_msg     = xqc_moq_on_announce_ok,
};

const xqc_moq_msg_base_t unsubscribe_base = {
    .type       = xqc_moq_msg_unsubscribe_type,
    .encode_len = xqc_moq_msg_encode_unsubscribe_len,
    .encode     = xqc_moq_msg_encode_unsubscribe,
    .decode     = xqc_moq_msg_decode_unsubscribe,
    .on_msg     = xqc_moq_on_unsubscribe,
};

const xqc_moq_msg_base_t subscribe_done_base = {
    .type       = xqc_moq_msg_subscribe_done_type,
    .encode_len = xqc_moq_msg_encode_subscribe_done_len,
    .encode     = xqc_moq_msg_encode_subscribe_done,
    .decode     = xqc_moq_msg_decode_subscribe_done,
    .on_msg     = xqc_moq_on_subscribe_done,
};

const xqc_moq_msg_base_t track_status_base = {
    .type       = xqc_moq_msg_track_status_type,
    .encode_len = xqc_moq_msg_encode_track_status_len,
    .encode     = xqc_moq_msg_encode_track_status,
    .decode     = xqc_moq_msg_decode_track_status,
    .on_msg     = xqc_moq_on_track_status,
};

const xqc_moq_msg_base_t track_status_ok_base = {
    .type       = xqc_moq_msg_track_status_ok_type,
    .encode_len = xqc_moq_msg_encode_track_status_ok_len,
    .encode     = xqc_moq_msg_encode_track_status_ok,
    .decode     = xqc_moq_msg_decode_track_status_ok,
    .on_msg     = xqc_moq_on_track_status_ok,
};

const xqc_moq_msg_base_t track_status_error_base = {
    .type       = xqc_moq_msg_track_status_error_type,
    .encode_len = xqc_moq_msg_encode_track_status_error_len,
    .encode     = xqc_moq_msg_encode_track_status_error,
    .decode     = xqc_moq_msg_decode_track_status_error,
    .on_msg     = xqc_moq_on_track_status_error,
};

const xqc_moq_msg_base_t goaway_base = {
    .type       = xqc_moq_msg_goaway_type,
    .encode_len = xqc_moq_msg_encode_goaway_len,
    .encode     = xqc_moq_msg_encode_goaway,
    .decode     = xqc_moq_msg_decode_goaway,
    .on_msg     = xqc_moq_on_goaway,
};

const xqc_moq_msg_base_t publish_base = {
    .type       = xqc_moq_msg_publish_type,
    .encode_len = xqc_moq_msg_encode_publish_len,
    .encode     = xqc_moq_msg_encode_publish,
    .decode     = xqc_moq_msg_decode_publish,
    .on_msg     = xqc_moq_on_publish,
};

const xqc_moq_msg_base_t publish_ok_base = {
    .type       = xqc_moq_msg_publish_ok_type,
    .encode_len = xqc_moq_msg_encode_publish_ok_len,
    .encode     = xqc_moq_msg_encode_publish_ok,
    .decode     = xqc_moq_msg_decode_publish_ok,
    .on_msg     = xqc_moq_on_publish_ok,
};

const xqc_moq_msg_base_t publish_error_base = {
    .type       = xqc_moq_msg_publish_error_type,
    .encode_len = xqc_moq_msg_encode_publish_error_len,
    .encode     = xqc_moq_msg_encode_publish_error,
    .decode     = xqc_moq_msg_decode_publish_error,
    .on_msg     = xqc_moq_on_publish_error,
};

const xqc_moq_msg_base_t subscribe_namespace_base = {
    .type       = xqc_moq_msg_subscribe_namespace_type,
    .encode_len = xqc_moq_msg_encode_subscribe_namespace_len,
    .encode     = xqc_moq_msg_encode_subscribe_namespace,
    .decode     = xqc_moq_msg_decode_subscribe_namespace,
    .on_msg     = xqc_moq_on_subscribe_namespace,
};

const xqc_moq_msg_base_t subscribe_namespace_ok_base = {
    .type       = xqc_moq_msg_subscribe_namespace_ok_type,
    .encode_len = xqc_moq_msg_encode_subscribe_namespace_ok_len,
    .encode     = xqc_moq_msg_encode_subscribe_namespace_ok,
    .decode     = xqc_moq_msg_decode_subscribe_namespace_ok,
    .on_msg     = xqc_moq_on_subscribe_namespace_ok,
};

void xqc_moq_msg_publish_namespace_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session);
void xqc_moq_msg_publish_namespace_done_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session);

void xqc_moq_on_publish_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);
void xqc_moq_on_publish_namespace_done(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

int xqc_moq_msg_publish_namespace_type() { return (int)XQC_MOQ_MSG_PUBLISH_NAMESPACE; }
int xqc_moq_msg_publish_namespace_done_type() { return (int)XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE; }

const xqc_moq_msg_base_t publish_namespace_base = {
    .type       = xqc_moq_msg_publish_namespace_type,
    .encode_len = xqc_moq_msg_encode_publish_namespace_len,
    .encode     = xqc_moq_msg_encode_publish_namespace,
    .decode     = xqc_moq_msg_decode_publish_namespace,
    .on_msg     = xqc_moq_on_publish_namespace,
};

const xqc_moq_msg_base_t publish_namespace_done_base = {
    .type       = xqc_moq_msg_publish_namespace_done_type,
    .encode_len = xqc_moq_msg_encode_publish_namespace_done_len,
    .encode     = xqc_moq_msg_encode_publish_namespace_done,
    .decode     = xqc_moq_msg_decode_publish_namespace_done,
    .on_msg     = xqc_moq_on_publish_namespace_done,
};


const xqc_moq_msg_base_t unsubscribe_namespace_base = {
    .type       = xqc_moq_msg_unsubscribe_namespace_type,
    .encode_len = xqc_moq_msg_encode_unsubscribe_namespace_len,
    .encode     = xqc_moq_msg_encode_unsubscribe_namespace,
    .decode     = xqc_moq_msg_decode_unsubscribe_namespace,
    .on_msg     = xqc_moq_on_unsubscribe_namespace,
};

uint8_t * xqc_moq_put_varint_length(uint8_t *buf, size_t length)
{
    if(length < 64){
        *buf = 0;
        buf++;
        printf("show length write: first bit = %d\n", *(buf-1));
        buf = xqc_put_varint(buf, length);
        printf("show length write: second bit = %d\n", *(buf-1));
        return buf;
    }else {
        xqc_put_varint(buf, length);
        return buf;
    }
}

xqc_int_t 
xqc_moq_length_read(uint8_t *buf, uint8_t* end, uint64_t *length)
{
    if (end - buf < 2 || buf == NULL || buf + 1 == NULL) {
        return -1;
    }

    uint64_t value = 0;

    value = (uint16_t)buf[0] << 8;
    value |= (uint16_t)buf[1];

    *length = value;

    return 2; // FIXED length
}

void *
xqc_moq_msg_create(xqc_moq_msg_type_t type, xqc_moq_stream_type_t stream_type, xqc_moq_session_t *session)
{
    if(stream_type == XQC_MOQ_STREAM_TYPE_CTL){
        for (xqc_int_t i = 0; i < sizeof(moq_msg_func_map) / sizeof(moq_msg_func_map[0]); i++) {
            if (moq_msg_func_map[i].type == type) {
                DEBUG_PRINTF("msg_type:%d, stream_type:%d\n",type,stream_type);
                return moq_msg_func_map[i].create(session);
            }
        }
    }else{
        for (xqc_int_t i = 0; i < sizeof(moq_msg_data_func_map) / sizeof(moq_msg_data_func_map[0]); i++) {
            if (moq_msg_data_func_map[i].type == type) {
                DEBUG_PRINTF("msg_type:%d, stream_type:%d\n",type,stream_type);
                return moq_msg_data_func_map[i].create(session);
            }
        }
    }
    DEBUG_PRINTF("Parse failed, msg_type:%d, stream_type:%d\n",type,stream_type);
    return NULL;
}

void
xqc_moq_msg_free(xqc_moq_msg_type_t type, void *msg)
{
    if (msg == NULL) {
        return;
    }
    for (xqc_int_t i = 0; i < sizeof(moq_msg_func_map) / sizeof(moq_msg_func_map[0]); i++) {
        if (moq_msg_func_map[i].type == type) {
            return moq_msg_func_map[i].free(msg);
        }
    }
}

void
xqc_moq_msg_free_ctl_stream(xqc_moq_msg_type_t type, void *msg)
{
    xqc_moq_msg_free(type, msg);
}

void xqc_moq_msg_free_data_stream(xqc_moq_msg_type_t type, void *msg)
{
    if(msg == NULL)
    {
        return;
    }
    for(xqc_int_t i = 0; i < sizeof(moq_msg_data_func_map) / sizeof(moq_msg_data_func_map[0]); i++)
    {
        if(moq_msg_data_func_map[i].type == type)
        {
            return moq_msg_data_func_map[i].free(msg);
        }
    }
}

void xqc_moq_msg_set_object_by_object(xqc_moq_object_t *obj, xqc_moq_object_stream_msg_t *msg)
{
    obj->subscribe_id = msg->subscribe_id;
    obj->track_alias = msg->track_alias;
    obj->group_id = msg->group_id;
    obj->object_id = msg->object_id;
    obj->send_order = msg->send_order;
    obj->status = msg->status;
    obj->extension_header = NULL;
    obj->extension_header_len = 0;
    obj->payload = msg->payload;
    obj->payload_len = msg->payload_len;
}

void xqc_moq_msg_set_object_by_subgroup_object(xqc_moq_object_t *obj, xqc_moq_subgroup_object_msg_t *msg)
{
    // obj->subscribe_id = msg->subgroup_header->subscribe_id; // set subscribe_id by track later
    obj->track_alias = msg->subgroup_header->track_alias;
    obj->group_id = msg->subgroup_header->group_id;
    obj->object_id = msg->object_id;
    obj->extension_header_len = msg->extension_header_len;
    obj->extension_header = msg->extension_header;
    obj->payload = msg->payload;
    obj->payload_len = msg->payload_len;
    obj->send_order = 0;
    obj->status = 0;
}



xqc_int_t xqc_moq_msg_encode_track_namespace_len(xqc_moq_msg_track_namespace_t *namespace)
{
    xqc_int_t length = 0;
    length += xqc_put_varint_len(namespace->track_namespace_num);
    for(size_t idx = 0; idx < namespace->track_namespace_num; idx++) {
        length += xqc_put_varint_len(namespace->track_namespace_len[idx]);
        length += namespace->track_namespace_len[idx];
    }
    return length;
}

xqc_int_t
xqc_moq_msg_encode_track_namespace(xqc_moq_msg_track_namespace_t *namespace,
                                   uint8_t *buf, size_t buf_len)
{
    uint8_t *p = buf;
    p = xqc_put_varint(p, namespace->track_namespace_num);
    for (size_t idx = 0; idx < namespace->track_namespace_num; idx++) {
        p = xqc_put_varint(p, namespace->track_namespace_len[idx]);
        xqc_memcpy(p, namespace->track_namespace[idx], namespace->track_namespace_len[idx]);
        p += namespace->track_namespace_len[idx];
    }
    return (xqc_int_t)(p - buf);
}

xqc_int_t
xqc_moq_msg_decode_track_namespace(uint8_t *buf, size_t buf_len,
    xqc_moq_decode_params_ctx_t *params_ctx, xqc_moq_msg_track_namespace_t *ns,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t val = 0;
    
    if (ns->track_namespace_num == 0) {
        ret = xqc_vint_read(buf + processed, buf + buf_len, &val);
        if (ret < 0) {
            *wait_more_data = 1;
            return processed;
        }
        processed += ret;
        ns->track_namespace_num = val;
        
        /* Allocate arrays */
        ns->track_namespace_len = xqc_calloc(val, sizeof(uint64_t));
        ns->track_namespace = xqc_calloc(val, sizeof(char*));
        if (ns->track_namespace_len == NULL || ns->track_namespace == NULL) {
            return -XQC_EMALLOC;
        }
    }
    
    /* Read namespace segments */
    while (val < ns->track_namespace_num) {
        uint64_t len = 0;
        ret = xqc_vint_read(buf + processed, buf + buf_len, &len);
        if (ret < 0) {
            *wait_more_data = 1;
            break;
        }
        processed += ret;
        
        /* Check if we have enough data for the segment */
        if (processed + (xqc_int_t)len > (xqc_int_t)buf_len) {
            *wait_more_data = 1;
            break;
        }
        
        ns->track_namespace_len[val] = len;
        ns->track_namespace[val] = xqc_malloc(len + 1);
        if (ns->track_namespace[val] == NULL) {
            return -XQC_EMALLOC;
        }
        xqc_memcpy(ns->track_namespace[val], buf + processed, len);
        ns->track_namespace[val][len] = '\0';
        processed += len;
        val++;
    }
    
    if (!*wait_more_data && val == ns->track_namespace_num) {
        *finish = 1;
    }
    
    return processed;
}


void xqc_moq_msg_set_object_by_track(xqc_moq_object_t *obj, xqc_moq_stream_header_track_msg_t *header,
    xqc_moq_track_stream_obj_msg_t *msg)
{
    obj->subscribe_id = header->subscribe_id;
    obj->track_alias = header->track_alias;
    obj->send_order = header->send_order;
    obj->group_id = msg->group_id;
    obj->object_id = msg->object_id;
    obj->status = msg->status;
    obj->extension_header = NULL;
    obj->extension_header_len = 0;
    obj->payload = msg->payload;
    obj->payload_len = msg->payload_len;
}

void xqc_moq_msg_set_object_by_group(xqc_moq_object_t *obj, xqc_moq_stream_header_group_msg_t *header,
    xqc_moq_group_stream_obj_msg_t *msg)
{
    obj->subscribe_id = header->subscribe_id;
    obj->track_alias = header->track_alias;
    obj->send_order = header->send_order;
    obj->group_id = header->group_id;
    obj->object_id = msg->object_id;
    obj->extension_header = NULL;
    obj->extension_header_len = 0;
    obj->status = msg->status;
    obj->payload = msg->payload;
    obj->payload_len = msg->payload_len;
}

xqc_int_t
xqc_moq_msg_decode_type(uint8_t *buf, size_t buf_len, xqc_moq_msg_type_t *type, xqc_int_t *wait_more_data)
{
    uint64_t val;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    ret = xqc_vint_read(buf, buf + buf_len, &val);
    if (ret < 0) {
        *wait_more_data = 1;
        return processed;
    }

    processed += ret;

    *type = val;
    printf("decode type=0x%llx\n", (unsigned long long)val);
    return processed;
}

void
xqc_moq_decode_msg_ctx_reset(xqc_moq_decode_msg_ctx_t *ctx)
{
    xqc_memzero(ctx, sizeof(*ctx));
}

void
xqc_moq_decode_params_ctx_reset(xqc_moq_decode_params_ctx_t *ctx)
{
    xqc_memzero(ctx, sizeof(*ctx));
}

xqc_moq_message_parameter_t *
xqc_moq_msg_alloc_params(xqc_int_t params_num)
{
    return xqc_calloc(params_num, sizeof(xqc_moq_message_parameter_t));
}
void
xqc_moq_msg_free_params(xqc_moq_message_parameter_t *params, xqc_int_t params_num)
{
    for (xqc_int_t i = 0; i < params_num; i++) {
        xqc_free(params[i].value);
    }
    xqc_free(params);
}

xqc_int_t
xqc_moq_msg_encode_params_len(xqc_moq_message_parameter_t *params, xqc_int_t params_num)
{
    xqc_int_t len = 0;
    xqc_moq_message_parameter_t *param;
    for (xqc_int_t i = 0; i < params_num; i++) {
        param = &params[i];
        len += xqc_put_varint_len(param->type);
        len += xqc_put_varint_len(param->length);
        if (param->length > 0) {
            len += param->length;
        }
    }
    return len;
}


xqc_int_t
xqc_moq_msg_encode_params_len_v11(xqc_moq_message_parameter_t *params, xqc_int_t params_num)
{
    xqc_int_t len = 0;
    xqc_moq_message_parameter_t *param;
    for (xqc_int_t i = 0; i < params_num; i++) {
        param = &params[i];
        len += xqc_put_varint_len(param->type);
        if(param->type & 1) 
            len += xqc_put_varint_len(param->length);
        // len += xqc_put_varint_len(param->length);
        if (param->length > 0) {
            len += param->length;
        }
    }
    return len;
}

//return encoded or error

xqc_int_t
xqc_moq_msg_encode_params_v11(xqc_moq_message_parameter_t *params, xqc_int_t params_num, uint8_t *buf, size_t buf_cap)
{
    uint8_t *p = buf;
    xqc_moq_message_parameter_t *param;

    if (xqc_moq_msg_encode_params_len_v11(params, params_num) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    for (xqc_int_t i = 0; i < params_num; i++) {
        param = &params[i];
        p = xqc_put_varint(p, param->type);
        if(param->type & 1) {
            p = xqc_put_varint(p, param->length);
        }
        if (param->length > 0) {
            xqc_memcpy(p, param->value, param->length);
            p += param->length;
        }
    }

    return p - buf;
}

xqc_int_t
xqc_moq_msg_encode_params(xqc_moq_message_parameter_t *params, xqc_int_t params_num, uint8_t *buf, size_t buf_cap)
{
    uint8_t *p = buf;
    xqc_moq_message_parameter_t *param;

    if (xqc_moq_msg_encode_params_len(params, params_num) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    for (xqc_int_t i = 0; i < params_num; i++) {
        param = &params[i];
        p = xqc_put_varint(p, param->type);
        p = xqc_put_varint(p, param->length);
        if (param->length > 0) {
            xqc_memcpy(p, param->value, param->length);
            p += param->length;
        }
    }

    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_one_param(uint8_t *buf, size_t buf_len, xqc_moq_decode_params_ctx_t *ctx,
    xqc_moq_message_parameter_t *param, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    *finish = 0;
    *wait_more_data = 0;
    
    // 安全检查：确保参数不为空
    if (param == NULL) {
        return -XQC_EPARAM;
    }

    switch (ctx->cur_field_idx) {
        case 0: //Parameter Type (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &param->type);
            if (ret < 0) {
                *wait_more_data = 1;
                return processed;
            }
            processed += ret;

            DEBUG_PRINTF("====>param[%d] type:%d\n",ctx->cur_param_idx, (int)param->type);
            if (param->type > XQC_MOQ_PARAM_EXTDATA_v11) {
                return -XQC_EILLEGAL_FRAME;
            }

            ctx->cur_field_idx = 1;
        case 1: //Parameter Length (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &param->length);
            if (ret < 0) {
                *wait_more_data = 1;
                return processed;
            }
            processed += ret;

            DEBUG_PRINTF("====>length:%d\n",(int)param->length);
            if (param->length < 0) {
                return -XQC_EILLEGAL_FRAME;
            }
            if (param->length > XQC_MOQ_MAX_PARAM_VALUE_LEN) {
                return -XQC_ELIMIT;
            }
            
            // 处理长度为0的情况
            if (param->length == 0) {
                param->value = NULL;
                *finish = 1;
                ctx->value_processed = 0;
                ctx->cur_field_idx = 0;
                return processed;
            }
            
            // 分配内存
            param->value = xqc_realloc(param->value, param->length);
            if (!param->value) {
                return -XQC_EMALLOC;
            }
            
            ctx->value_processed = 0;
            ctx->cur_field_idx = 2;
        case 2: //Parameter Value (..)
            if (buf_len - processed == 0) {
                *wait_more_data = 1;
                return processed;
            }
            
            // 确保value指针有效
            if (!param->value) {
                return -XQC_EILLEGAL_FRAME;
            }

            if (param->length - ctx->value_processed <= buf_len - processed) {
                xqc_memcpy(param->value + ctx->value_processed, buf + processed,
                           param->length - ctx->value_processed);
                processed += param->length - ctx->value_processed;

                DEBUG_PRINTF("====>value:");
                for (int i = 0; i < param->length; i++)
                    DEBUG_PRINTF("0x%x ", param->value[i]);
                DEBUG_PRINTF("\n");

                *finish = 1;

                ctx->value_processed = 0;
                ctx->cur_field_idx = 0;
                return processed;
            } else {
                xqc_memcpy(param->value + ctx->value_processed, buf + processed, buf_len - processed);
                ctx->value_processed += buf_len - processed;
                processed += buf_len - processed;

                *wait_more_data = 1;

                return processed;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }
}


xqc_int_t
xqc_moq_msg_decode_one_param_v11(uint8_t *buf, size_t buf_len, xqc_moq_decode_params_ctx_t *ctx,
    xqc_moq_message_parameter_t *param, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    *finish = 0;
    *wait_more_data = 0;
    
    // 安全检查：确保参数不为空
    if (param == NULL) {
        return -XQC_EPARAM;
    }

    switch (ctx->cur_field_idx) {
        case 0: //Parameter Type (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &param->type);
            printf("==>param[%d] type:%d\n",ctx->cur_param_idx, (int)param->type);
            if (ret < 0) {
                *wait_more_data = 1;
                return processed;
            }
            processed += ret;

            DEBUG_PRINTF("====>param[%d] type:%d\n",ctx->cur_param_idx, (int)param->type);
            if (param->type > XQC_MOQ_PARAM_EXTDATA_v11) {
                return -XQC_EILLEGAL_FRAME;
            }
            if(param->type & 1) {
                ctx->cur_field_idx = 1;
            } else {
                ctx->cur_field_idx = 2;
                goto idx2;
            }
        case 1: //Parameter Length (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &param->length);
            if (ret < 0) {
                *wait_more_data = 1;
                return processed;
            }
            processed += ret;

            DEBUG_PRINTF("====>length:%d\n",(int)param->length);
            if (param->length < 0) {
                return -XQC_EILLEGAL_FRAME;
            }
            if (param->length > XQC_MOQ_MAX_PARAM_VALUE_LEN) {
                return -XQC_ELIMIT;
            }
            
            // 处理长度为0的情况
            if (param->length == 0) {
                param->value = NULL;
                *finish = 1;
                ctx->value_processed = 0;
                ctx->cur_field_idx = 0;
                return processed;
            }
            
            // 分配内存
            param->value = xqc_realloc(param->value, param->length);
            if (!param->value) {
                return -XQC_EMALLOC;
            }
            
            ctx->value_processed = 0;
            ctx->cur_field_idx = 2;
        case 2: //Parameter Value (..)
            idx2:
            if (buf_len - processed == 0) {
                *wait_more_data = 1;
                return processed;
            }
            
            // 确保value指针有效
            // if (!param->value) {
            //     return -XQC_EILLEGAL_FRAME;
            // }
            

            if(param->type & 1) {
                if (param->length - ctx->value_processed <= buf_len - processed) {
                    xqc_memcpy(param->value + ctx->value_processed, buf + processed,
                               param->length - ctx->value_processed);
                    processed += param->length - ctx->value_processed;
    
                    DEBUG_PRINTF("====>value:");
                    for (int i = 0; i < param->length; i++)
                        DEBUG_PRINTF("0x%x ", param->value[i]);
                    DEBUG_PRINTF("\n");
    
                    *finish = 1;
    
                    ctx->value_processed = 0;
                    ctx->cur_field_idx = 0;
                    return processed;
                } else {
                    xqc_memcpy(param->value + ctx->value_processed, buf + processed, buf_len - processed);
                    ctx->value_processed += buf_len - processed;
                    processed += buf_len - processed;
    
                    *wait_more_data = 1;
    
                    return processed;
                }
            } else {
                uint64_t max_request_id = 0;
                ret = xqc_vint_read(buf + processed, buf + buf_len, &max_request_id);
                param->value = xqc_realloc(param->value, sizeof(uint64_t));
                *(uint64_t *)param->value = max_request_id;
                if (ret < 0) {
                    *wait_more_data = 1;
                    return processed;
                }
                processed += ret;
                *finish = 1;
                ctx->value_processed = 0;
                ctx->cur_field_idx = 0;
                return processed;
            }

            
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }
}


xqc_int_t
xqc_moq_msg_decode_params(uint8_t *buf, size_t buf_len, xqc_moq_decode_params_ctx_t *ctx,
    xqc_moq_message_parameter_t *params, xqc_int_t params_num, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t params_finish = 0;
    *finish = 0;
    *wait_more_data = 0;
    
    // 安全检查：如果参数数量为0或params为空，直接完成
    if (params_num == 0 || params == NULL) {
        *finish = 1;
        xqc_moq_decode_params_ctx_reset(ctx);
        return processed;
    }

    for (; ctx->cur_param_idx < params_num; ctx->cur_param_idx++) {
        xqc_moq_message_parameter_t *param = &params[ctx->cur_param_idx];
        ret = xqc_moq_msg_decode_one_param_v11(buf + processed, buf_len - processed, ctx, param, &params_finish, wait_more_data);
        if (ret < 0) {
            return ret;
        }
        processed += ret;
        if (*wait_more_data == 1) {
            return processed;
        }
        if (params_finish == 1) {
            if (ctx->cur_param_idx == params_num - 1) {
                *finish = 1;
                /* Reset param ctx when decode params finish */
                xqc_moq_decode_params_ctx_reset(ctx);
                return processed;
            }
        }
    }
    return processed;
}

/**
 * CLIENT_SETUP Message
 */

void *
xqc_moq_msg_create_client_setup(xqc_moq_session_t *session)
{
    xqc_moq_client_setup_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_client_setup_init_handler(&msg->msg_base,session);
    return msg;
}

void
xqc_moq_msg_free_client_setup(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t*)msg;
    xqc_free(client_setup->versions);
    xqc_moq_msg_free_params(client_setup->params, client_setup->params_num);
    xqc_free(client_setup);
}

xqc_int_t
xqc_moq_msg_client_setup_type()
{
    return XQC_MOQ_MSG_CLIENT_SETUP;
}

void
xqc_moq_msg_client_setup_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    if(session->version >= XQC_MOQ_VERSION_DRAFT_11) {
        session->version = XQC_MOQ_CUR_VERSION;
        *msg_base = client_setup_base_v11;
    } else if(session->version == XQC_MOQ_VERSION_DRAFT_05 || session->version == 0) {
        session->version = XQC_MOQ_VERSION_DRAFT_05;
        *msg_base = client_setup_base_v05;
    }
    else {
        xqc_log(session->log, XQC_LOG_ERROR, "|illegal version|");
    }
}

xqc_int_t
xqc_moq_msg_encode_client_setup_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_CLIENT_SETUP);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;

    len += xqc_put_varint_len(client_setup->params_num);
    len += xqc_moq_msg_encode_params_len_v11(client_setup->params, client_setup->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_client_setup(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t*)msg_base;
    uint64_t length = xqc_moq_msg_encode_client_setup_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_CLIENT_SETUP) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_CLIENT_SETUP);
    p = xqc_moq_put_varint_length(p, length);

    p = xqc_put_varint(p, client_setup->params_num);

    ret = xqc_moq_msg_encode_params_v11(client_setup->params, client_setup->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_client_setup(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0; // test for moxygen
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t length_expected = 0;  // actually, we can read the full packet without this param
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: // Length of Client Setup Message (i)
            if(XQC_MOQ_CUR_VERSION == XQC_MOQ_VERSION_DRAFT_05) {
                msg_ctx->cur_field_idx = 3;
            }
            else {
                ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length_expected);
                length_expected = length_expected + ret;
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                DEBUG_PRINTF("==>length_expected:%d\n",(int)length_expected);
                msg_ctx->cur_field_idx = 1;
            }
        case 1: //Number of Parameters (i) ...
            ret = xqc_vint_read(buf + processed, buf + buf_len, &client_setup->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)client_setup->params_num);

            if (client_setup->params_num == 0) {
                *finish = 1;
                break;
            }
            if (client_setup->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            client_setup->params = xqc_moq_msg_alloc_params(client_setup->params_num);

            msg_ctx->cur_field_idx = 2;
        case 2: //Setup Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            client_setup->params, client_setup->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

xqc_int_t
xqc_moq_msg_encode_client_setup_len_v05(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_CLIENT_SETUP);
    len += xqc_put_varint_len(client_setup->versions_num);
    for (xqc_int_t i = 0; i < client_setup->versions_num; i++) {
        len += xqc_put_varint_len(client_setup->versions[i]);
    }
    len += xqc_put_varint_len(client_setup->params_num);
    len += xqc_moq_msg_encode_params_len(client_setup->params, client_setup->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_client_setup_v05(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
        xqc_int_t ret = 0;
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t*)msg_base;
    if (xqc_moq_msg_encode_client_setup_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_CLIENT_SETUP);
    p = xqc_put_varint(p, client_setup->versions_num);
    for (int i = 0; i < client_setup->versions_num; i++) {
        p = xqc_put_varint(p, client_setup->versions[i]);
    }
    p = xqc_put_varint(p, client_setup->params_num);

    ret = xqc_moq_msg_encode_params(client_setup->params, client_setup->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

xqc_int_t 
xqc_moq_msg_decode_client_setup_v05(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Number of Supported Versions (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &client_setup->versions_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>versions_num:%d\n",(int)client_setup->versions_num);
            if (client_setup->versions_num > XQC_MOQ_MAX_VERSIONS || client_setup->versions_num <= 0) {
                return -XQC_ELIMIT;
            }
            client_setup->versions = xqc_calloc(client_setup->versions_num, sizeof(uint64_t));

            msg_ctx->cur_field_idx = 1;
        case 1: //Supported Version (i) ...
            for (; msg_ctx->cur_array_idx < client_setup->versions_num; msg_ctx->cur_array_idx++) {
                ret = xqc_vint_read(buf + processed, buf + buf_len,
                                    &client_setup->versions[msg_ctx->cur_array_idx]);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                DEBUG_PRINTF("====>version:0x%x\n",(int)client_setup->versions[msg_ctx->cur_array_idx]);
            }
            if (*wait_more_data == 1) {
                break;
            }
            msg_ctx->cur_field_idx = 2;
            msg_ctx->cur_array_idx = 0;
        case 2: //Number of Parameters (i) ...
            ret = xqc_vint_read(buf + processed, buf + buf_len, &client_setup->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)client_setup->params_num);

            if (client_setup->params_num == 0) {
                *finish = 1;
                break;
            }
            if (client_setup->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            client_setup->params = xqc_moq_msg_alloc_params(client_setup->params_num);

            msg_ctx->cur_field_idx = 3;
        case 3: //Setup Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            client_setup->params, client_setup->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * SERVER_SETUP Message
 */

void *
xqc_moq_msg_create_server_setup(xqc_moq_session_t *session)
{
    xqc_moq_server_setup_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_server_setup_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_server_setup(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_server_setup_msg_t *server_setup = (xqc_moq_server_setup_msg_t*)msg;
    xqc_moq_msg_free_params(server_setup->params, server_setup->params_num);
    xqc_free(server_setup);
}

xqc_int_t
xqc_moq_msg_server_setup_type()
{
    return XQC_MOQ_MSG_SERVER_SETUP;
}

void
xqc_moq_msg_server_setup_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    if(session != NULL){
        DEBUG_PRINTF("==>session->version:%d\n",(int)session->version);
    }
    if(session==NULL || session->version >= XQC_MOQ_VERSION_DRAFT_11) {
        // TODO
        *msg_base = server_setup_base;
    } else {
        *msg_base = server_setup_base;
    }
}

xqc_int_t
xqc_moq_msg_encode_server_setup_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0; // length of params
    xqc_moq_server_setup_msg_t *server_setup = (xqc_moq_server_setup_msg_t*)msg_base;
    if(XQC_MOQ_CUR_VERSION >= XQC_MOQ_VERSION_DRAFT_11) { // TODO
        len += xqc_put_varint_len(XQC_MOQ_MSG_SERVER_SETUP);
    }
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(server_setup->params_num);
    len += xqc_moq_msg_encode_params_len_v11(server_setup->params, server_setup->params_num);
    
    DEBUG_PRINTF("==>tot_length:%d, length_param:%d\n",(int)len,(int)length_param);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_server_setup(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_server_setup_msg_t *server_setup = (xqc_moq_server_setup_msg_t*)msg_base;
    uint64_t tot_length = xqc_moq_msg_encode_server_setup_len(msg_base);
    if (tot_length > buf_cap) {
        DEBUG_PRINTF("==>tot_length:%d, buf_cap:%d\n",(int)tot_length,(int)buf_cap);
        return -XQC_EILLEGAL_FRAME;
    }
    uint64_t length = tot_length - xqc_put_varint_len(XQC_MOQ_MSG_SERVER_SETUP) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SERVER_SETUP);
    if(XQC_MOQ_CUR_VERSION >= XQC_MOQ_VERSION_DRAFT_11) {
        p = xqc_moq_put_varint_length(p, length);
    }
    p = xqc_put_varint(p, server_setup->params_num);

    ret = xqc_moq_msg_encode_params_v11(server_setup->params, server_setup->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;
    printf("encoded length in server setup: %d\n", (int)(p - buf));

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_server_setup(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    printf("==>xqc_moq_msg_decode_server_setup\n");
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_server_setup_msg_t *server_setup = (xqc_moq_server_setup_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    uint64_t length_expected = 0;
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            if(XQC_MOQ_CUR_VERSION >= XQC_MOQ_VERSION_DRAFT_11) { // for test
                // ret = xqc_vint_read(buf + processed, buf + buf_len, &length_expected);
                ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length_expected);
                printf("decode server setup length_expected = %lld", length_expected);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                if(ret == 1) ret++;
                processed += ret;
                printf("decode server setup ret = %d\n", ret);
            }
            msg_ctx->cur_field_idx = 1;
        case 1: //Number of Parameters (i) ...
            ret = xqc_vint_read(buf + processed, buf + buf_len, &server_setup->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)server_setup->params_num);

            if (server_setup->params_num == 0) {
                *finish = 1;
                break;
            }
            if (server_setup->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            server_setup->params = xqc_moq_msg_alloc_params(server_setup->params_num);

            msg_ctx->cur_field_idx = 2;
        case 2: //Setup Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            server_setup->params, server_setup->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                printf("==>decode server setup finish\n");
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
        }

    return processed;
}


/**
 * SUBSCRIBE Message
 */

void *
xqc_moq_msg_create_subscribe_v05(xqc_moq_session_t *session)
{
    xqc_moq_subscribe_msg_t_v05 *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_init_handler(&msg->msg_base,session);
    return msg;
}

void *
xqc_moq_msg_create_subscribe_v13(xqc_moq_session_t *session)
{
    xqc_moq_subscribe_msg_t_v13 *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_init_handler(&msg->msg_base,session);
    return msg;
}

void
xqc_moq_msg_free_subscribe_v05(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_msg_t_v05 *subscribe = (xqc_moq_subscribe_msg_t_v05*)msg;
    xqc_moq_msg_free_track_namespace(subscribe->track_namespace);
    if(subscribe->track_name!=NULL)
    {
        xqc_free(subscribe->track_name);
    }
    xqc_moq_msg_free_params(subscribe->params, subscribe->params_num);
    xqc_free(subscribe);
}

void
xqc_moq_msg_free_subscribe_v13(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_msg_t_v13 *subscribe = (xqc_moq_subscribe_msg_t_v13*)msg;
    xqc_moq_msg_free_track_namespace(subscribe->track_namespace);
    if(subscribe->track_name!=NULL)
    {
        xqc_free(subscribe->track_name);
    }
    xqc_moq_msg_free_params(subscribe->params, subscribe->params_num);
    xqc_free(subscribe);
}


xqc_int_t
xqc_moq_msg_subscribe_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE;
}

void
xqc_moq_msg_subscribe_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    if(session->version >= XQC_MOQ_VERSION_DRAFT_11) {
        *msg_base = subscribe_base_v13;
    } else if(session->version == XQC_MOQ_VERSION_DRAFT_05) {
        *msg_base = subscribe_base_v05;
    }
}

xqc_int_t
xqc_moq_msg_encode_subscribe_len_v13(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_msg_t_v13 *subscribe = (xqc_moq_subscribe_msg_t_v13*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe->request_id);
    len += xqc_put_varint_len(subscribe->track_namespace->track_namespace_num);
    for(size_t i = 0 ; i < subscribe->track_namespace->track_namespace_num ; i++)
    {
        len += xqc_put_varint_len(subscribe->track_namespace->track_namespace_len[i]);
        len += subscribe->track_namespace->track_namespace_len[i];
    }
    len += xqc_put_varint_len(subscribe->track_name_len);
    len += subscribe->track_name_len;
    len += XQC_MOQ_SUB_PRIORITY_SIZE;
    len += XQC_MOQ_GROUP_ORDER_SIZE;
    len += XQC_MOQ_FORWARD_SIZE;
    len += xqc_put_varint_len(subscribe->filter_type);
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
        || subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        len += xqc_put_varint_len(subscribe->start_group_id);
        len += xqc_put_varint_len(subscribe->start_object_id);
    }
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        len += xqc_put_varint_len(subscribe->end_group_id);
        len += xqc_put_varint_len(subscribe->end_object_id);
    }
    len += xqc_put_varint_len(subscribe->params_num);
    len += xqc_moq_msg_encode_params_len_v11(subscribe->params, subscribe->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_v13(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_msg_t_v13 *subscribe = (xqc_moq_subscribe_msg_t_v13*)msg_base;
    uint64_t length = xqc_moq_msg_encode_subscribe_len_v13(msg_base); 
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length -= xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE) + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    subscribe->length = length;

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE);
    p = xqc_moq_put_varint_length(p, subscribe->length);
    p = xqc_put_varint(p, subscribe->request_id);
    p = xqc_put_varint(p, subscribe->track_namespace->track_namespace_num);
    for(size_t i = 0 ; i < subscribe->track_namespace->track_namespace_num ; i++)
    {
        p = xqc_put_varint(p, subscribe->track_namespace->track_namespace_len[i]);
        xqc_memcpy(p, subscribe->track_namespace->track_namespace[i], subscribe->track_namespace->track_namespace_len[i]);
        p += subscribe->track_namespace->track_namespace_len[i];
    }
    p = xqc_put_varint(p, subscribe->track_name_len);
    xqc_memcpy(p, subscribe->track_name, subscribe->track_name_len);
    p += subscribe->track_name_len;
    *p++ = subscribe->subscriber_priority; /* Subscriber Priority (8 bits) */
    *p++ = subscribe->group_order; /* Group Order (8 bits) */
    *p++ = subscribe->forward; /* Forward (8 bits) */
    p = xqc_put_varint(p, subscribe->filter_type);
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
        || subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        p = xqc_put_varint(p, subscribe->start_group_id);
        p = xqc_put_varint(p, subscribe->start_object_id);
    }
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        p = xqc_put_varint(p, subscribe->end_group_id);
        p = xqc_put_varint(p, subscribe->end_object_id);
    }
    p = xqc_put_varint(p, subscribe->params_num);
    ret = xqc_moq_msg_encode_params(subscribe->params, subscribe->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;
    // show binary content of subscribe_msg
    printf("DEBUG show binary content of subscribe_msg\n");
    for(uint8_t *t = buf; t < p; t++)
    {
        printf("0x%x ", *t);
    }
    printf("\n");

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_subscribe_v13(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t val = 0;
    xqc_moq_subscribe_msg_t_v13 *subscribe = (xqc_moq_subscribe_msg_t_v13 *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;

    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &subscribe->length);
            printf("subscribe v13 decode length: %llu\n", subscribe->length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>length:%d\n",(int)subscribe->length);
            msg_ctx->cur_field_idx = 1;
        case 1: // Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>request_id:%d\n",(int)subscribe->request_id);
            msg_ctx->cur_field_idx = 2;
        case 2: //Track Namespace (tuple)
            if(subscribe->track_namespace == NULL)
            {
                subscribe->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
                subscribe->track_namespace->track_namespace_num = 0;
                subscribe->track_namespace->track_namespace = NULL;
                subscribe->track_namespace->track_namespace_len = NULL;
            }
            if(subscribe->track_namespace->track_namespace_num == 0)
            {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->track_namespace->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                msg_ctx->cur_array_idx = 0;
                subscribe->track_namespace->track_namespace = xqc_calloc(subscribe->track_namespace->track_namespace_num, sizeof(char *));
                subscribe->track_namespace->track_namespace_len = xqc_calloc(subscribe->track_namespace->track_namespace_num, sizeof(uint64_t));
            }
            for(size_t i = msg_ctx->cur_array_idx ; i < subscribe->track_namespace->track_namespace_num ; i++)
            {
                if (subscribe->track_namespace->track_namespace_len[i] == 0) {
                    ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe->track_namespace->track_namespace_len[i]);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    DEBUG_PRINTF("==>namespace_len:%d\n",(int)subscribe->track_namespace_len);
                    processed += ret;
                }
                if (subscribe->track_namespace->track_namespace[i] == NULL) {
                    if (subscribe->track_namespace->track_namespace_len[i] > XQC_MOQ_MAX_NAME_LEN) {
                        return -XQC_ELIMIT;
                    }
                    subscribe->track_namespace->track_namespace[i] = xqc_calloc(1, subscribe->track_namespace->track_namespace_len[i]+1);
                }
                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                } else if (subscribe->track_namespace->track_namespace_len[i] - msg_ctx->str_processed <= buf_len - processed) {
                    xqc_memcpy(subscribe->track_namespace->track_namespace[i] + msg_ctx->str_processed, buf + processed,
                            subscribe->track_namespace->track_namespace_len[i] - msg_ctx->str_processed);
                    processed += subscribe->track_namespace->track_namespace_len[i] - msg_ctx->str_processed;
                    msg_ctx->str_processed = 0; //track_namespace finish
                } else {
                    xqc_memcpy(subscribe->track_namespace->track_namespace[i] + msg_ctx->str_processed, buf + processed,
                            buf_len - processed);
                    msg_ctx->str_processed += buf_len - processed;
                    processed += buf_len - processed;
                    *wait_more_data = 1;
                    break;
                }
            }
            DEBUG_PRINTF("==>track_namespace:%s\n",subscribe->track_namespace);
            msg_ctx->cur_field_idx = 3;
        case 3: // Track Name(tuple) for version07    Track Name (b) for version05
            if (subscribe->track_name_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe->track_name_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                DEBUG_PRINTF("==>name_len:%d\n",(int)subscribe->track_name_len);
                processed += ret;
            }
            if (subscribe->track_name == NULL) {
                if (subscribe->track_name_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                subscribe->track_name = xqc_calloc(1, subscribe->track_name_len + 1);
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (subscribe->track_name_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(subscribe->track_name + msg_ctx->str_processed, buf + processed,
                        subscribe->track_name_len - msg_ctx->str_processed);
                processed += subscribe->track_name_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0; //track_name finish
            } else {
                xqc_memcpy(subscribe->track_name + msg_ctx->str_processed, buf + processed,
                        buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            
            DEBUG_PRINTF("==>track_name:%s\n",subscribe->track_name);
            msg_ctx->cur_field_idx = 4;
        case 4: //Subscriber Priority(8)
            if (buf_len - processed < 1) {
                *wait_more_data = 1;
                break;
            }
            subscribe->subscriber_priority = buf[processed];
            processed += 1;

            DEBUG_PRINTF("==>subscriber_priority:%d\n",(int)subscribe->subscriber_priority);
            msg_ctx->cur_field_idx = 5;
        case 5: //Group Order(8)
            if (buf_len - processed < 1) {
                *wait_more_data = 1;
                break;
            }
            subscribe->group_order = buf[processed];
            processed += 1;

            DEBUG_PRINTF("==>group_order:%d\n",(int)subscribe->group_order);
            msg_ctx->cur_field_idx = 6;
        case 6: //Forward(8)
            if (buf_len - processed < 1) {
                *wait_more_data = 1;
                break;
            }
            subscribe->forward = buf[processed];
            processed += 1;

            DEBUG_PRINTF("==>forward:%d\n",(int)subscribe->forward);
            msg_ctx->cur_field_idx = 7;
        case 7: //Filter Type (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->filter_type);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            printf("subscribe v13 msg filter type: %d\n", (int)subscribe->filter_type);
            processed += ret;
            DEBUG_PRINTF("==>filter_type:%d\n",(int)subscribe->filter_type);
            if (subscribe->filter_type == XQC_MOQ_FILTER_LARGEST_OBJECT
                || subscribe->filter_type == XQC_MOQ_FILTER_NEXT_GROUP_START) {
                msg_ctx->cur_field_idx = 12;
                goto idx12;
            } else if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
                       || subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 8;
            } else {
                return -XQC_EPARAM;
            }
        case 8: //StartGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->start_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_group_id:%d\n",(int)subscribe->start_group_id);
            msg_ctx->cur_field_idx = 9;
        case 9: //StartObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->start_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_object_id:%d\n",(int)subscribe->start_object_id);
            if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 10;
            } else {
                msg_ctx->cur_field_idx = 12;
                goto idx12;
            }
        case 10: //EndGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->end_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_group_id:%d\n",(int)subscribe->end_group_id);
            msg_ctx->cur_field_idx = 11;
        case 11: //EndObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->end_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_object_id:%d\n",(int)subscribe->end_object_id);
            msg_ctx->cur_field_idx = 12;
        case 12: //Number of Parameters (i) ...
        idx12:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)subscribe->params_num);

            if (subscribe->params_num == 0) {
                *finish = 1;
                break;
            }
            if (subscribe->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            subscribe->params = xqc_moq_msg_alloc_params(subscribe->params_num);

            msg_ctx->cur_field_idx = 13;
        case 13: //Subscribe Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            subscribe->params, subscribe->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_len_v05(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_msg_t_v05 *subscribe = (xqc_moq_subscribe_msg_t_v05*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE);
    len += xqc_put_varint_len(subscribe->subscribe_id);
    len += xqc_put_varint_len(subscribe->track_alias);
    len += xqc_put_varint_len(subscribe->track_namespace->track_namespace_len[0]);
    len += subscribe->track_namespace->track_namespace_len[0];
    len += xqc_put_varint_len(subscribe->track_name_len);
    len += subscribe->track_name_len;
    len += xqc_put_varint_len(subscribe->filter_type);
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
        || subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        len += xqc_put_varint_len(subscribe->start_group_id);
        len += xqc_put_varint_len(subscribe->start_object_id);
    }
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        len += xqc_put_varint_len(subscribe->end_group_id);
        len += xqc_put_varint_len(subscribe->end_object_id);
    }
    len += xqc_put_varint_len(subscribe->params_num);
    len += xqc_moq_msg_encode_params_len(subscribe->params, subscribe->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_v05(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_msg_t_v05 *subscribe = (xqc_moq_subscribe_msg_t_v05*)msg_base;
    if (xqc_moq_msg_encode_subscribe_len_v05(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE);
    p = xqc_put_varint(p, subscribe->subscribe_id);
    p = xqc_put_varint(p, subscribe->track_alias);
    p = xqc_put_varint(p, subscribe->track_namespace->track_namespace_len[0]);
    xqc_memcpy(p, subscribe->track_namespace->track_namespace[0], subscribe->track_namespace->track_namespace_len[0]);
    p += subscribe->track_namespace->track_namespace_len[0];
    p = xqc_put_varint(p, subscribe->track_name_len);
    xqc_memcpy(p, subscribe->track_name, subscribe->track_name_len);
    p += subscribe->track_name_len;
    p = xqc_put_varint(p, subscribe->filter_type);
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
        || subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        p = xqc_put_varint(p, subscribe->start_group_id);
        p = xqc_put_varint(p, subscribe->start_object_id);
    }
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        p = xqc_put_varint(p, subscribe->end_group_id);
        p = xqc_put_varint(p, subscribe->end_object_id);
    }
    p = xqc_put_varint(p, subscribe->params_num);
    ret = xqc_moq_msg_encode_params(subscribe->params, subscribe->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}
xqc_int_t
xqc_moq_msg_decode_subscribe_v05(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t val = 0;
    xqc_moq_subscribe_msg_t_v05 *subscribe = (xqc_moq_subscribe_msg_t_v05 *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe->subscribe_id);
            msg_ctx->cur_field_idx = 1;
        case 1: //Track Alias (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>track_alias:%d\n",(int)subscribe->track_alias);
            subscribe->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
            subscribe->track_namespace->track_namespace_len = xqc_calloc(1, sizeof(uint64_t));
            msg_ctx->cur_field_idx = 2;
        case 2: //Track Namespace (b)
            if (subscribe->track_namespace->track_namespace_len[0] == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe->track_namespace->track_namespace_len[0]);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                subscribe->track_namespace->track_namespace = xqc_calloc(1,  sizeof(char *));
                subscribe->track_namespace->track_namespace[0] = xqc_calloc(1, subscribe->track_namespace->track_namespace_len[0] + 1);
                DEBUG_PRINTF("==>namespace_len:%d\n",(int)subscribe->track_namespace_len);
                processed += ret;
            }
            if (subscribe->track_namespace->track_namespace_len[0] > XQC_MOQ_MAX_NAME_LEN) {
                return -XQC_ELIMIT;
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (subscribe->track_namespace->track_namespace_len[0] - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(subscribe->track_namespace->track_namespace[0] + msg_ctx->str_processed, buf + processed,
                           subscribe->track_namespace->track_namespace_len[0] - msg_ctx->str_processed);
                processed += subscribe->track_namespace->track_namespace_len[0] - msg_ctx->str_processed;
                msg_ctx->str_processed = 0; //track_namespace finish
            } else {
                xqc_memcpy(subscribe->track_namespace + msg_ctx->str_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            DEBUG_PRINTF("==>track_namespace:%s\n",subscribe->track_namespace);
            msg_ctx->cur_field_idx = 3;
        case 3: //Track Name (b)
            if (subscribe->track_name_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe->track_name_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                DEBUG_PRINTF("==>name_len:%d\n",(int)subscribe->track_name_len);
                processed += ret;
            }
            if (subscribe->track_name == NULL) {
                if (subscribe->track_name_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                subscribe->track_name = xqc_calloc(1, subscribe->track_name_len + 1);
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (subscribe->track_name_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(subscribe->track_name + msg_ctx->str_processed, buf + processed,
                           subscribe->track_name_len - msg_ctx->str_processed);
                processed += subscribe->track_name_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0; //track_name finish
            } else {
                xqc_memcpy(subscribe->track_name + msg_ctx->str_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            DEBUG_PRINTF("==>track_name:%s\n",subscribe->track_name);
            msg_ctx->cur_field_idx = 4;
        case 4: //Filter Type (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->filter_type);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>filter_type:%d\n",(int)subscribe->filter_type);
            if (subscribe->filter_type == XQC_MOQ_FILTER_LAST_GROUP
                || subscribe->filter_type == XQC_MOQ_FILTER_LAST_OBJECT) {
                msg_ctx->cur_field_idx = 9;
                goto idx9;
            } else if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
                       || subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 5;
            } else {
                return -XQC_EPARAM;
            }
        case 5: //StartGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->start_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_group_id:%d\n",(int)subscribe->start_group_id);
            msg_ctx->cur_field_idx = 6;
        case 6: //StartObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->start_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_object_id:%d\n",(int)subscribe->start_object_id);
            if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 7;
            } else {
                msg_ctx->cur_field_idx = 9;
                goto idx9;
            }
        case 7: //EndGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->end_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_group_id:%d\n",(int)subscribe->end_group_id);
            msg_ctx->cur_field_idx = 8;
        case 8: //EndObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->end_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_object_id:%d\n",(int)subscribe->end_object_id);
            msg_ctx->cur_field_idx = 9;
        case 9: //Number of Parameters (i) ...
        idx9:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)subscribe->params_num);

            if (subscribe->params_num == 0) {
                *finish = 1;
                break;
            }
            if (subscribe->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            subscribe->params = xqc_moq_msg_alloc_params(subscribe->params_num);

            msg_ctx->cur_field_idx = 10;
        case 10: //Subscribe Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            subscribe->params, subscribe->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}


/**
 * SUBSCRIBE_UPDATE Message
 */

void *
xqc_moq_msg_create_subscribe_update_v05(xqc_moq_session_t *session)
{
    xqc_moq_subscribe_update_msg_t_v05 *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_update_init_handler(&msg->msg_base, session);
    return msg;
}

void *
xqc_moq_msg_create_subscribe_update_v13(xqc_moq_session_t *session)
{
    xqc_moq_subscribe_update_msg_t_v13 *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_update_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_subscribe_update_v05(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_update_msg_t_v05 *subscribe_update = (xqc_moq_subscribe_update_msg_t_v05*)msg;
    xqc_moq_msg_free_params(subscribe_update->params, subscribe_update->params_num);
    xqc_free(subscribe_update);
}

void
xqc_moq_msg_free_subscribe_update_v13(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_update_msg_t_v13 *subscribe_update = (xqc_moq_subscribe_update_msg_t_v13*)msg;
    xqc_moq_msg_free_params(subscribe_update->params, subscribe_update->params_num);
    xqc_free(subscribe_update);
}

xqc_int_t
xqc_moq_msg_subscribe_update_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_UPDATE;
}

void
xqc_moq_msg_subscribe_update_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = subscribe_update_base_v13;
    // if(session->version >= XQC_MOQ_SUPPORTED_VERSION_14) {
    //     *msg_base = subscribe_update_base_v13;
    // } else if(session->version == XQC_MOQ_SUPPORTED_VERSION_05) {
    //     *msg_base = subscribe_update_base_v05;
    // }
}

xqc_int_t
xqc_moq_msg_encode_subscribe_update_len_v05(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_update_msg_t_v05 *subscribe_update = (xqc_moq_subscribe_update_msg_t_v05*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_UPDATE);
    len += xqc_put_varint_len(subscribe_update->subscribe_id);
    len += xqc_put_varint_len(subscribe_update->start_group_id);
    len += xqc_put_varint_len(subscribe_update->start_object_id);
    len += xqc_put_varint_len(subscribe_update->end_group_id);
    len += xqc_put_varint_len(subscribe_update->end_object_id);
    len += xqc_put_varint_len(subscribe_update->params_num);
    len += xqc_moq_msg_encode_params_len(subscribe_update->params, subscribe_update->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_update_v05(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_update_msg_t_v05 *subscribe_update = (xqc_moq_subscribe_update_msg_t_v05*)msg_base;
    if (xqc_moq_msg_encode_subscribe_update_len_v05(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_UPDATE);
    p = xqc_put_varint(p, subscribe_update->subscribe_id);
    p = xqc_put_varint(p, subscribe_update->start_group_id);
    p = xqc_put_varint(p, subscribe_update->start_object_id);
    p = xqc_put_varint(p, subscribe_update->end_group_id);
    p = xqc_put_varint(p, subscribe_update->end_object_id);
    p = xqc_put_varint(p, subscribe_update->params_num);
    ret = xqc_moq_msg_encode_params(subscribe_update->params, subscribe_update->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_subscribe_update_v05(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t val = 0;
    xqc_moq_subscribe_update_msg_t_v05 *subscribe_update = (xqc_moq_subscribe_update_msg_t_v05 *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: //subscribe_update ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_update->subscribe_id);
            msg_ctx->cur_field_idx = 1;
        case 1: //StartGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->start_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_group_id:%d\n",(int)subscribe_update->start_group_id);
            msg_ctx->cur_field_idx = 2;
        case 2: //StartObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->start_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_object_id:%d\n",(int)subscribe_update->start_object_id);
            msg_ctx->cur_field_idx = 3;
        case 3: //EndGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->end_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_group_id:%d\n",(int)subscribe_update->end_group_id);
            msg_ctx->cur_field_idx = 4;
        case 4: //EndObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->end_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_object_id:%d\n",(int)subscribe_update->end_object_id);
            msg_ctx->cur_field_idx = 5;
        case 5: //Number of Parameters (i) ...
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)subscribe_update->params_num);

            if (subscribe_update->params_num == 0) {
                *finish = 1;
                break;
            }
            if (subscribe_update->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            subscribe_update->params = xqc_moq_msg_alloc_params(subscribe_update->params_num);

            msg_ctx->cur_field_idx = 6;
        case 6: //subscribe_update Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            subscribe_update->params, subscribe_update->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}


xqc_int_t
xqc_moq_msg_encode_subscribe_update_len_v13(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_update_msg_t_v13 *subscribe_update = (xqc_moq_subscribe_update_msg_t_v13*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_UPDATE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe_update->subscribe_id);
    len += xqc_put_varint_len(subscribe_update->start_group_id);
    len += xqc_put_varint_len(subscribe_update->start_object_id);
    len += xqc_put_varint_len(subscribe_update->end_group);
    len += xqc_put_varint_len(subscribe_update->subscriber_priority);
    len += xqc_put_varint_len(subscribe_update->forward);
    len += xqc_put_varint_len(subscribe_update->params_num);
    len += xqc_moq_msg_encode_params_len(subscribe_update->params, subscribe_update->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_update_v13(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_update_msg_t_v13 *subscribe_update = (xqc_moq_subscribe_update_msg_t_v13*)msg_base;
    uint64_t length = xqc_moq_msg_encode_subscribe_update_len_v13(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_UPDATE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_UPDATE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, subscribe_update->subscribe_id);
    p = xqc_put_varint(p, subscribe_update->start_group_id);
    p = xqc_put_varint(p, subscribe_update->start_object_id);
    p = xqc_put_varint(p, subscribe_update->end_group);
    p = xqc_put_varint(p, subscribe_update->subscriber_priority);
    p = xqc_put_varint(p, subscribe_update->forward);
    p = xqc_put_varint(p, subscribe_update->params_num);
    ret = xqc_moq_msg_encode_params(subscribe_update->params, subscribe_update->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_subscribe_update_v13(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t val = 0;
    xqc_moq_subscribe_update_msg_t_v13 *subscribe_update = (xqc_moq_subscribe_update_msg_t_v13 *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    uint64_t subscriber_priority = 0;
    uint64_t forward = 0;
    uint64_t length = 0;
    uint64_t start_group_id = 0;
    switch (msg_ctx->cur_field_idx) {
        case 0: //length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //subscribe_update ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_update->subscribe_id);
            msg_ctx->cur_field_idx = 2;
        case 2: //StartGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->start_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_group_id:%d\n",(int)subscribe_update->start_group_id);
            msg_ctx->cur_field_idx = 3;
        case 3: //StartObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->start_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_object_id:%d\n",(int)subscribe_update->start_object_id);
            msg_ctx->cur_field_idx = 4;
        case 4: //EndGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->end_group);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_group_id:%d\n",(int)subscribe_update->end_group);
            msg_ctx->cur_field_idx = 5;
        case 5: //Subscriber Priority (8)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscriber_priority);
            subscribe_update->subscriber_priority = (uint8_t)subscriber_priority;
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscriber_priority:%d\n",(int)subscribe_update->subscriber_priority);
            msg_ctx->cur_field_idx = 6;
        case 6: //Forward (8)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &forward);
            subscribe_update->forward = (uint8_t)forward;
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>forward:%d\n",(int)subscribe_update->forward);
            msg_ctx->cur_field_idx = 7;
        case 7: //Number of Parameters (i) ...
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)subscribe_update->params_num);

            if (subscribe_update->params_num == 0) {
                *finish = 1;
                break;
            }
            if (subscribe_update->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            subscribe_update->params = xqc_moq_msg_alloc_params(subscribe_update->params_num);

            msg_ctx->cur_field_idx = 8;
        case 8: //subscribe_update Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            subscribe_update->params, subscribe_update->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}


/**
 * SUBSCRIBE_OK Message
 */

void *
xqc_moq_msg_create_subscribe_ok(xqc_moq_session_t *session)
{
    xqc_moq_subscribe_ok_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_ok_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_subscribe_ok(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg;
    xqc_free(subscribe_ok);
}

xqc_int_t
xqc_moq_msg_subscribe_ok_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_OK;
}

void
xqc_moq_msg_subscribe_ok_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    if(session->version >= XQC_MOQ_VERSION_DRAFT_11) {
        // printf("subscribe_ok_base_v11\n");
        *msg_base = subscribe_ok_base_v11;
    } else if(session->version == XQC_MOQ_VERSION_DRAFT_05) {
        printf("subscribe_ok_v05\n");
        *msg_base = subscribe_ok_v05;
    }
}

xqc_int_t
xqc_moq_msg_encode_subscribe_ok_len_v11(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_OK);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe_ok->subscribe_id);
    len += xqc_put_varint_len(subscribe_ok->track_alias); /* Track Alias for v11 */
    len += xqc_put_varint_len(subscribe_ok->expire_ms);
    len += XQC_MOQ_GROUP_ORDER_SIZE; /* Group Order (8 bits) */
    len += XQC_MOQ_CONTENT_EXISTS_SIZE; /* Content Exists (8 bits) */
    if (subscribe_ok->content_exist == 1) {
        len += xqc_put_varint_len(subscribe_ok->largest_group_id);
        len += xqc_put_varint_len(subscribe_ok->largest_object_id);
    }
    // add param
    len += xqc_put_varint_len(subscribe_ok->params_num);
    len += xqc_moq_msg_encode_params_len(subscribe_ok->params, subscribe_ok->params_num);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_ok_v11(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg_base;
    xqc_int_t tot_length = xqc_moq_msg_encode_subscribe_ok_len_v11(msg_base);
    if (tot_length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_int_t length = tot_length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_OK) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_OK);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, subscribe_ok->subscribe_id);
    p = xqc_put_varint(p, subscribe_ok->track_alias); /* Track Alias for v11 */
    p = xqc_put_varint(p, subscribe_ok->expire_ms);
    *p++ = subscribe_ok->group_order; /* Group Order (8 bits) */
    *p++ = subscribe_ok->content_exist; /* Content Exists (8 bits) */
    if (subscribe_ok->content_exist == 1) {
        p = xqc_put_varint(p, subscribe_ok->largest_group_id);
        p = xqc_put_varint(p, subscribe_ok->largest_object_id);
    }
    p = xqc_put_varint(p, subscribe_ok->params_num);
    ret = xqc_moq_msg_encode_params(subscribe_ok->params, subscribe_ok->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_subscribe_ok_v11(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    printf("==>decode subscribe ok v11\n");
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t *)msg_base;
    printf("==>show binary content of subscribe ok\n");
    for(uint8_t *t = buf; t < buf + buf_len; t++)
    {
        printf("0x%x ", *t);
    }
    printf("\n");
    uint64_t length_expected = 0;
    switch (msg_ctx->cur_field_idx) {
        case 0: //length(i)
            // ret = xqc_vint_read(buf + processed, buf + buf_len, &length_expected);
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if(length_expected <= 0) {
                DEBUG_PRINTF("length_expected <= 0\n");
            }
            processed += ret;
        case 1: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_ok->subscribe_id);
            msg_ctx->cur_field_idx = 2;
        case 2: //Track Alias (i) - v11
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>track_alias:%d\n",(int)subscribe_ok->track_alias);
            msg_ctx->cur_field_idx = 3;
        case 3: //Expires (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->expire_ms);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>expires:%d\n",(int)subscribe_ok->expire_ms);
            msg_ctx->cur_field_idx = 4;
        case 4: //Group Order (8)
            if (buf_len - processed < 1) {
                *wait_more_data = 1;
                break;
            }
            // subscribe_ok->group_order = buf[processed];
            ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe_ok->group_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>group_order:%d\n",(int)subscribe_ok->group_order);
            msg_ctx->cur_field_idx = 5;
        case 5: //Content Exists (8)
            if (buf_len - processed < 1) {
                *wait_more_data = 1;
                break;
            }
            // subscribe_ok->content_exist = buf[processed];
            ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe_ok->content_exist);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>content_exist:%d\n",(int)subscribe_ok->content_exist);

            if (subscribe_ok->content_exist == 0) {
                msg_ctx->cur_field_idx = 8;
                goto idx8;
            }
            else if(subscribe_ok->content_exist == 1) {
                msg_ctx->cur_field_idx = 6;
            }
            else {
                return -XQC_EPARAM;
            }
        case 6: //[Largest Group ID (i)]
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->largest_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>largest_group_id:%d\n",(int)subscribe_ok->largest_group_id);

            msg_ctx->cur_field_idx = 7;
        case 7: //[Largest Object ID (i)]
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->largest_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>largest_object_id:%d\n",(int)subscribe_ok->largest_object_id);
            msg_ctx->cur_field_idx = 8;
        case 8:
            idx8:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>params_num:%d\n",(int)subscribe_ok->params_num);

            if (subscribe_ok->params_num == 0) {
                *finish = 1;
                break;
            }
            if (subscribe_ok->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            subscribe_ok->params = xqc_moq_msg_alloc_params(subscribe_ok->params_num);

            msg_ctx->cur_field_idx = 9;
        case 9: //subscribe_ok Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, &msg_ctx->decode_params_ctx,
                                            subscribe_ok->params, subscribe_ok->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
                printf("==>decode subscribe ok v11 finish\n");
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_ok_len_v05(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_OK);
    len += xqc_put_varint_len(subscribe_ok->subscribe_id);
    len += xqc_put_varint_len(subscribe_ok->expire_ms);
    len += xqc_put_varint_len(subscribe_ok->content_exist);
    if (subscribe_ok->content_exist == 1) {
        len += xqc_put_varint_len(subscribe_ok->largest_group_id);
        len += xqc_put_varint_len(subscribe_ok->largest_object_id);
    }
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_ok_v05(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg_base;
    if (xqc_moq_msg_encode_subscribe_ok_len_v05(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_OK);
    p = xqc_put_varint(p, subscribe_ok->subscribe_id);
    p = xqc_put_varint(p, subscribe_ok->expire_ms);
    p = xqc_put_varint(p, subscribe_ok->content_exist);
    if (subscribe_ok->content_exist == 1) {
        p = xqc_put_varint(p, subscribe_ok->largest_group_id);
        p = xqc_put_varint(p, subscribe_ok->largest_object_id);
    }

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_subscribe_ok_v05(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_ok->subscribe_id);

            msg_ctx->cur_field_idx = 1;
        case 1: //Expires (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->expire_ms);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>expires:%d\n",(int)subscribe_ok->expire_ms);

            msg_ctx->cur_field_idx = 2;
        case 2: //ContentExists (f)
            ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe_ok->content_exist);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>content_exists:%d\n",(int)subscribe_ok->content_exists);

            if (subscribe_ok->content_exist == 0) {
                *finish = 1;
                break;
            }
            msg_ctx->cur_field_idx = 3;
        case 3: //[Largest Group ID (i)]
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->largest_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>largest_group_id:%d\n",(int)subscribe_ok->largest_group_id);

            msg_ctx->cur_field_idx = 4;
        case 4: //[Largest Object ID (i)]
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->largest_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>largest_object_id:%d\n",(int)subscribe_ok->largest_object_id);

            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * SUBSCRIBE_ERROR Message
 */

void *
xqc_moq_msg_create_subscribe_error(xqc_moq_session_t *session)
{
    xqc_moq_subscribe_error_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_error_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_subscribe_error(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_error_msg_t *subscribe_error = (xqc_moq_subscribe_error_msg_t*)msg;
    xqc_free(subscribe_error->reason_phrase);
    xqc_free(subscribe_error);
}

xqc_int_t
xqc_moq_msg_subscribe_error_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_ERROR;
}

void
xqc_moq_msg_subscribe_error_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = subscribe_error_base;
}


// PUBLISH Message

void *
xqc_moq_msg_create_publish(xqc_moq_session_t *session)
{
    xqc_moq_publish_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_publish(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t*)msg;
    xqc_moq_msg_free_track_namespace(publish->track_namespace);
    if (publish->track_name != NULL) {
        xqc_free(publish->track_name);
    }
    xqc_moq_msg_free_params(publish->params, publish->params_num);
    xqc_free(publish);
}

xqc_int_t
xqc_moq_msg_publish_type()
{
    return XQC_MOQ_MSG_PUBLISH;
}

void
xqc_moq_msg_publish_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = publish_base;
}


// PUBLISH_OK Message

void *
xqc_moq_msg_create_publish_ok(xqc_moq_session_t *session)
{
    xqc_moq_publish_ok_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    msg->params_num = -1;  /* Mark as uninitialized for decode */
    xqc_moq_msg_publish_ok_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_publish_ok(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t*)msg;
    xqc_moq_msg_free_params(publish_ok->params, publish_ok->params_num);
    xqc_free(publish_ok);
}

xqc_int_t
xqc_moq_msg_publish_ok_type()
{
    return XQC_MOQ_MSG_PUBLISH_OK;
}

void
xqc_moq_msg_publish_ok_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = publish_ok_base;
}


// PUBLISH_ERROR Message

void *
xqc_moq_msg_create_publish_error(xqc_moq_session_t *session)
{
    xqc_moq_publish_error_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_error_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_publish_error(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_error_msg_t *publish_error = (xqc_moq_publish_error_msg_t*)msg;
    if (publish_error->reason != NULL) {
        xqc_free(publish_error->reason);
    }
    xqc_free(publish_error);
}

xqc_int_t
xqc_moq_msg_publish_error_type()
{
    return XQC_MOQ_MSG_PUBLISH_ERROR;
}

void
xqc_moq_msg_publish_error_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = publish_error_base;
}

// PUBLISH Message Encoding/Decoding

xqc_int_t
xqc_moq_msg_encode_publish_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t*)msg_base;
    
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(publish->request_id);
    len += xqc_moq_msg_encode_track_namespace_len(publish->track_namespace);
    len += xqc_put_varint_len(publish->track_name_len);
    len += publish->track_name_len;
    len += xqc_put_varint_len(publish->track_alias);
    len += XQC_MOQ_GROUP_ORDER_SIZE; // Group Order (8 bits)
    len += XQC_MOQ_CONTENT_EXISTS_SIZE; // ContentExists (8 bits)
    if (publish->content_exists) {
        len += xqc_put_varint_len(publish->largest_group_id);
        len += xqc_put_varint_len(publish->largest_object_id);
    }
    len += XQC_MOQ_FORWARD_SIZE; // Forward (8 bits)
    len += xqc_put_varint_len(publish->params_num);
    len += xqc_moq_msg_encode_params_len(publish->params, publish->params_num);
    
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t*)msg_base;
    uint64_t length = xqc_moq_msg_encode_publish_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length -= xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH) + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    publish->length = length;
    
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH);
    p = xqc_moq_put_varint_length(p, publish->length);
    p = xqc_put_varint(p, publish->request_id);
    
    // Encode track namespace
    p = xqc_put_varint(p, publish->track_namespace->track_namespace_num);
    for (size_t i = 0; i < publish->track_namespace->track_namespace_num; i++) {
        p = xqc_put_varint(p, publish->track_namespace->track_namespace_len[i]);
        xqc_memcpy(p, publish->track_namespace->track_namespace[i], publish->track_namespace->track_namespace_len[i]);
        p += publish->track_namespace->track_namespace_len[i];
    }
    
    // Encode track name
    p = xqc_put_varint(p, publish->track_name_len);
    xqc_memcpy(p, publish->track_name, publish->track_name_len);
    p += publish->track_name_len;
    
    p = xqc_put_varint(p, publish->track_alias);
    
    if (publish->content_exists) {
        p = xqc_put_varint(p, publish->largest_group_id);
        p = xqc_put_varint(p, publish->largest_object_id);
    }
    
    p = xqc_put_varint(p, publish->forward);
    
    // Encode parameters
    p = xqc_put_varint(p, publish->params_num);
    ret = xqc_moq_msg_encode_params(publish->params, publish->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;
    
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
                          xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
                          xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t val = 0;
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    uint64_t group_order = 0;
    uint64_t content_exists = 0;
    uint64_t forward = 0;
    
    switch (msg_ctx->cur_field_idx) {
        case 0: // Length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &publish->length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
            
        case 1: // Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
            
        case 2: // Track Namespace (tuple)
            if (msg_ctx->cur_array_idx == 0) {
                // Read namespace count
                ret = xqc_vint_read(buf + processed, buf + buf_len, &val);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                
                publish->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
                publish->track_namespace->track_namespace_num = val;
                publish->track_namespace->track_namespace_len = xqc_calloc(val, sizeof(uint64_t));
                publish->track_namespace->track_namespace = xqc_calloc(val, sizeof(char*));
                
                msg_ctx->cur_array_idx = 1;
            }
            
            // Read namespace entries
            while (msg_ctx->cur_array_idx <= publish->track_namespace->track_namespace_num * 2) {
                uint64_t idx = (msg_ctx->cur_array_idx - 1) / 2;
                
                if (msg_ctx->cur_array_idx % 2 == 1) {
                    // Read namespace length
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->track_namespace->track_namespace_len[idx]);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                    publish->track_namespace->track_namespace[idx] = xqc_malloc(publish->track_namespace->track_namespace_len[idx] + 1);
                    
                } else {
                    // Read namespace value
                    if (processed + publish->track_namespace->track_namespace_len[idx] > buf_len) {
                        *wait_more_data = 1;
                        break;
                    }
                    
                    xqc_memcpy(publish->track_namespace->track_namespace[idx], 
                        buf + processed, 
                        publish->track_namespace->track_namespace_len[idx]);
                    publish->track_namespace->track_namespace[idx][publish->track_namespace->track_namespace_len[idx]] = '\0';
                    processed += publish->track_namespace->track_namespace_len[idx];
                }
                
                msg_ctx->cur_array_idx++;
            }
            
            if (*wait_more_data) {
                break;
            }
            
            msg_ctx->cur_field_idx = 3;
            msg_ctx->cur_array_idx = 0;
            
        case 3: // Track Name Length (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->track_name_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            publish->track_name = xqc_malloc(publish->track_name_len + 1);
            memset(publish->track_name, 0, publish->track_name_len + 1);
            msg_ctx->cur_field_idx = 4;
            
        case 4: /* Track Name (..) */
            if (processed + publish->track_name_len > buf_len) {
                *wait_more_data = 1;
                break;
            }
            xqc_memcpy(publish->track_name, buf + processed, publish->track_name_len);
            publish->track_name[publish->track_name_len] = '\0';
            processed += publish->track_name_len;
            msg_ctx->cur_field_idx = 5;
            
        case 5: /* Track Alias (i) */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 6;
            
        case 6: /* Group Order (8) */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &group_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            publish->group_order = group_order;
            processed += ret;
            msg_ctx->cur_field_idx = 7;
            
        case 7: /* ContentExists (8) */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &content_exists);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            publish->content_exists = content_exists;
            msg_ctx->cur_field_idx = 8;
            
        case 8: /* [Largest (Location),] */
            if (publish->content_exists) {
                /* Largest Group ID */
                ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->largest_group_id);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                
                /* Largest Object ID */
                ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->largest_object_id);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
            }
            msg_ctx->cur_field_idx = 9;
            
        case 9: /* Forward (8) */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &forward);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            publish->forward = forward;
            processed += ret;
            msg_ctx->cur_field_idx = 10;
            
        case 10: /* Number of Parameters (i) */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            
            if (publish->params_num > 0) {
                publish->params = xqc_calloc(publish->params_num, sizeof(xqc_moq_message_parameter_t));
            }
            msg_ctx->cur_field_idx = 11;
            
        case 11: /* Parameters (..) ... */
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                          publish->params, publish->params_num,
                                          &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
            
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    
    return processed;
}


// PUBLISH_OK Message Encoding/Decoding

xqc_int_t
xqc_moq_msg_encode_publish_ok_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t*)msg_base;
    
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_OK);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE; /* Fixed 2 bytes for message length */
    len += xqc_put_varint_len(publish_ok->request_id);
    
    len += xqc_put_varint_len(publish_ok->params_num);
    len += xqc_moq_msg_encode_params_len(publish_ok->params, publish_ok->params_num);
    
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t*)msg_base;
    uint64_t length = xqc_moq_msg_encode_publish_ok_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length =  length - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_OK) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_OK);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, publish_ok->request_id);

    
    p = xqc_put_varint(p, publish_ok->params_num);
    if(publish_ok->params_num > 0){
        ret = xqc_moq_msg_encode_params_v11(publish_ok->params, publish_ok->params_num, p, buf + buf_cap - p);
        if (ret < 0) {
            return ret;
        }
        p += ret;
    }

    
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish_ok(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
                             xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
                             xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    printf("xqc_moq_msg_decode_publish_ok\n");
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    uint64_t length_expected = 0;
    uint64_t params_num_val = 0;
    switch (msg_ctx->cur_field_idx) {
        case 0: /* length (16) */
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: /* Request ID (i) */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: /* params_num */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &params_num_val);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            publish_ok->params_num = params_num_val;
            
            if (publish_ok->params_num > 0) {
                publish_ok->params = xqc_calloc(publish_ok->params_num, sizeof(xqc_moq_message_parameter_t));
                if (publish_ok->params == NULL) {
                    return -XQC_EMALLOC;
                }
            }
            msg_ctx->cur_field_idx = 3;
        case 3: /* params */
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                          publish_ok->params, publish_ok->params_num,
                                          &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
            
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    
    return processed;
}


/**
 * PUBLISH_ERROR Message Encoding/Decoding
 */

xqc_int_t
xqc_moq_msg_encode_publish_error_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_error_msg_t *publish_error = (xqc_moq_publish_error_msg_t*)msg_base;
    
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_ERROR);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(publish_error->request_id);
    len += xqc_put_varint_len(publish_error->error_code);
    len += xqc_put_varint_len(publish_error->reason_len);
    len += publish_error->reason_len;
    
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_publish_error_msg_t *publish_error = (xqc_moq_publish_error_msg_t*)msg_base;
    uint64_t length = xqc_moq_msg_encode_publish_error_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length -= xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_ERROR) + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_ERROR);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, publish_error->request_id);
    p = xqc_put_varint(p, publish_error->error_code);
    p = xqc_put_varint(p, publish_error->reason_len);
    
    if (publish_error->reason_len > 0 && publish_error->reason != NULL) {
        xqc_memcpy(p, publish_error->reason, publish_error->reason_len);
        p += publish_error->reason_len;
    }
    
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
                                xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
                                xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_publish_error_msg_t *publish_error = (xqc_moq_publish_error_msg_t *)msg_base;
    uint64_t length = 0;
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if(ret == 1) ret +=1;
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: /* Request ID (i) */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_error->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
            
        case 2: /* Error Code (i) */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_error->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
            
        case 3: /* Error Reason Length */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_error->reason_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            
            if (publish_error->reason_len > 0) {
                publish_error->reason = xqc_malloc(publish_error->reason_len + 1);
                memset(publish_error->reason, 0, publish_error->reason_len + 1);
            }
            msg_ctx->cur_field_idx = 4;
            
        case 4: /* Error Reason */
            if (publish_error->reason_len > 0) {
                if (processed + publish_error->reason_len > buf_len) {
                    *wait_more_data = 1;
                    break;
                }
                
                xqc_memcpy(publish_error->reason, buf + processed, publish_error->reason_len);
                processed += publish_error->reason_len;
            }
            
            *finish = 1;
            break;
            
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    
    return processed;
}

//return processed or error
xqc_int_t 
xqc_moq_msg_encode_subscribe_error_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_error_msg_t *subscribe_error = (xqc_moq_subscribe_error_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_ERROR);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe_error->subscribe_id);
    len += xqc_put_varint_len(subscribe_error->error_code);
    len += xqc_put_varint_len(subscribe_error->reason_phrase_len);
    len += subscribe_error->reason_phrase_len;
    len += xqc_put_varint_len(subscribe_error->track_alias);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_error_msg_t *subscribe_error = (xqc_moq_subscribe_error_msg_t*)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_subscribe_error_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_ERROR) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_ERROR);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, subscribe_error->subscribe_id);
    p = xqc_put_varint(p, subscribe_error->error_code);
    p = xqc_put_varint(p, subscribe_error->reason_phrase_len);
    if (subscribe_error->reason_phrase_len > 0) {
        xqc_memcpy(p, subscribe_error->reason_phrase, subscribe_error->reason_phrase_len);
        p += subscribe_error->reason_phrase_len;
    }
    p = xqc_put_varint(p, subscribe_error->track_alias);
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_subscribe_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    printf("==>decode subscribe error\n");
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_subscribe_error_msg_t *subscribe_error = (xqc_moq_subscribe_error_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_error->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_error->subscribe_id);

            msg_ctx->cur_field_idx = 1;
        case 1: //Error Code (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_error->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>error_code:%d\n",(int)subscribe_error->error_code);

            msg_ctx->cur_field_idx = 2;
        case 2: //Reason Phrase (b)
            if (subscribe_error->reason_phrase_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe_error->reason_phrase_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                DEBUG_PRINTF("==>reason_phrase_len:%d\n",(int)subscribe_error->reason_phrase_len);
                processed += ret;
            }
            if (subscribe_error->reason_phrase == NULL) {
                if (subscribe_error->reason_phrase_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                subscribe_error->reason_phrase = xqc_calloc(1, subscribe_error->reason_phrase_len + 1);
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (subscribe_error->reason_phrase_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(subscribe_error->reason_phrase + msg_ctx->str_processed, buf + processed,
                           subscribe_error->reason_phrase_len - msg_ctx->str_processed);
                processed += subscribe_error->reason_phrase_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0; //reason_phrase finish
            } else {
                xqc_memcpy(subscribe_error->reason_phrase + msg_ctx->str_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            DEBUG_PRINTF("==>reason_phrase:%s\n",subscribe_error->reason_phrase);
            msg_ctx->cur_field_idx = 3;
        case 3: //Track Alias (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_error->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>track_alias:%d\n",(int)subscribe_error->track_alias);

            *finish = 1;
            break;
        default:
                return -XQC_EILLEGAL_FRAME;
            }

    return processed;
}
/**
 * ANNOUNCE_OK Message
 */

void
xqc_moq_msg_announce_ok_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = announce_ok_base;
}

void *
xqc_moq_msg_create_announce_ok(xqc_moq_session_t *session)
{
    xqc_moq_announce_ok_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_announce_ok_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_announce_ok(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_announce_ok_msg_t *announce_ok = (xqc_moq_announce_ok_msg_t *)msg;
    xqc_free(announce_ok);
}

xqc_int_t
xqc_moq_msg_encode_announce_ok_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_announce_ok_msg_t *announce_ok = (xqc_moq_announce_ok_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_ANNOUNCE_OK);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE; // Length field
    len += xqc_put_varint_len(announce_ok->request_id);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_announce_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_announce_ok_msg_t *announce_ok = (xqc_moq_announce_ok_msg_t*)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_announce_ok_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_ANNOUNCE_OK) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_ANNOUNCE_OK);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, announce_ok->request_id);
    return p - buf;
}



/**
 * OBJECT_STREAM Message
 */

void *
xqc_moq_msg_create_object_stream(xqc_moq_session_t *session)
{
    xqc_moq_object_stream_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_object_stream_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_object_stream(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_object_stream_msg_t *object_stream = (xqc_moq_object_stream_msg_t *)msg;
    xqc_free(object_stream->payload);
    xqc_free(object_stream);
}

xqc_int_t
xqc_moq_msg_object_stream_type()
{
    return XQC_MOQ_MSG_OBJECT_STREAM;
}

void
xqc_moq_msg_object_stream_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = object_stream_base;
}

xqc_int_t
xqc_moq_msg_encode_object_stream_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_object_stream_msg_t *object = (xqc_moq_object_stream_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_OBJECT_STREAM);
    len += xqc_put_varint_len(object->subscribe_id);
    len += xqc_put_varint_len(object->track_alias);
    len += xqc_put_varint_len(object->group_id);
    len += xqc_put_varint_len(object->object_id);
    len += xqc_put_varint_len(object->send_order);
    len += xqc_put_varint_len(object->status);
    len += object->payload_len;

    return len;
}

xqc_int_t
xqc_moq_msg_encode_object_stream(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_object_stream_msg_t *object = (xqc_moq_object_stream_msg_t*)msg_base;
    if (xqc_moq_msg_encode_object_stream_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_OBJECT_STREAM);
    p = xqc_put_varint(p, object->subscribe_id);
    p = xqc_put_varint(p, object->track_alias);
    p = xqc_put_varint(p, object->group_id);
    p = xqc_put_varint(p, object->object_id);
    p = xqc_put_varint(p, object->send_order);
    p = xqc_put_varint(p, object->status);

    xqc_memcpy(p, object->payload, object->payload_len);
    p += object->payload_len;
    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_object_stream(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_object_stream_msg_t *object = (xqc_moq_object_stream_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)object->subscribe_id);
            msg_ctx->cur_field_idx = 1;
        case 1: //Track Alias (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>track_alias:%d\n",(int)object->track_alias);
            msg_ctx->cur_field_idx = 2;
        case 2: //Group ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>group_id:%d\n",(int)object->group_id);
            msg_ctx->cur_field_idx = 3;
        case 3: //Object ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>object_id:%d\n",(int)object->object_id);
            msg_ctx->cur_field_idx = 4;
        case 4: //Object Send Order (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->send_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>send_order:%d\n",(int)object->send_order);
            msg_ctx->cur_field_idx = 5;
        case 5: //Object Status (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->status);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>status:%d\n",(int)object->status);
            msg_ctx->cur_field_idx = 6;
        case 6: //Object Payload (..)
            if (buf_len - processed == 0) {
                    *wait_more_data = 1;
                    break;
                }
            object->payload_len = msg_ctx->payload_processed + buf_len - processed;
            if (object->payload_len > XQC_MOQ_MAX_OBJECT_LEN) {
                return -XQC_ELIMIT;
            }
            object->payload = xqc_realloc(object->payload, object->payload_len);
            xqc_memcpy(object->payload + msg_ctx->payload_processed, buf + processed, buf_len - processed);
            msg_ctx->payload_processed += buf_len - processed;
            processed += buf_len - processed;
            if (stream_fin == 1) {
            *finish = 1;
            } else {
                *wait_more_data = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * STREAM_HEADER_TRACK Object
 */

void *
xqc_moq_msg_create_track_stream_obj(xqc_moq_session_t *session)
{
    xqc_moq_track_stream_obj_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_track_stream_obj_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_track_stream_obj(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_track_stream_obj_msg_t *track_stream_obj = (xqc_moq_track_stream_obj_msg_t *)msg;
    xqc_free(track_stream_obj->payload);
    xqc_free(track_stream_obj);
}

xqc_int_t
xqc_moq_msg_track_stream_obj_type()
{
    return XQC_MOQ_MSG_TRACK_STREAM_OBJECT;
}

xqc_int_t
xqc_moq_msg_subgroup_type()
{
    return XQC_MOQ_SUBGROUP;
}

xqc_int_t
xqc_moq_msg_subgroup_object_type()
{
    return XQC_MOQ_SUBGROUP_OBJECT;
}

xqc_int_t
xqc_moq_msg_subgroup_object_ext_type()
{
    return XQC_MOQ_SUBGROUP_OBJECT_EXT;
}

xqc_int_t
xqc_moq_msg_announce_type()
{
    return XQC_MOQ_MSG_ANNOUNCE;
}

xqc_int_t 
xqc_moq_msg_announce_error_type()
{
    return XQC_MOQ_MSG_ANNOUNCE_ERROR;
}

xqc_int_t 
xqc_moq_msg_fetch_type()
{
    return XQC_MOQ_MSG_FETCH;
}

xqc_int_t
xqc_moq_msg_announce_ok_type()
{
    return XQC_MOQ_MSG_ANNOUNCE_OK;
}

xqc_int_t 
xqc_moq_msg_unsubscribe_type()
{
    return XQC_MOQ_MSG_UNSUBSCRIBE;
}

void
xqc_moq_msg_track_stream_obj_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = track_stream_obj_base;
}

xqc_int_t
xqc_moq_msg_encode_track_stream_obj_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_track_stream_obj_msg_t *object = (xqc_moq_track_stream_obj_msg_t*)msg_base;
    //len += xqc_put_varint_len(XQC_MOQ_MSG_TRACK_STREAM_OBJECT); No type on the wire
    len += xqc_put_varint_len(object->group_id);
    len += xqc_put_varint_len(object->object_id);
    len += xqc_put_varint_len(object->payload_len);
    if (object->payload_len == 0) {
        len += xqc_put_varint_len(object->status);
    } else {
        len += object->payload_len;
    }
    return len;
}

xqc_int_t
xqc_moq_msg_encode_track_stream_obj(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_track_stream_obj_msg_t *object = (xqc_moq_track_stream_obj_msg_t*)msg_base;
    if (xqc_moq_msg_encode_track_stream_obj_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    //p = xqc_put_varint(p, XQC_MOQ_MSG_TRACK_STREAM_OBJECT); No type on the wire
    p = xqc_put_varint(p, object->group_id);
    p = xqc_put_varint(p, object->object_id);
    p = xqc_put_varint(p, object->payload_len);
    if (object->payload_len == 0) {
        p = xqc_put_varint(p, object->status);
    } else {
        xqc_memcpy(p, object->payload, object->payload_len);
        p += object->payload_len;
    }
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_track_stream_obj(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_track_stream_obj_msg_t *object = (xqc_moq_track_stream_obj_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Group ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>group_id:%d\n",(int)object->group_id);
            msg_ctx->cur_field_idx = 1;
        case 1: //Object ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>object_id:%d\n",(int)object->object_id);
            msg_ctx->cur_field_idx = 2;
        case 2: //Object Payload Length (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->payload_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (object->payload_len) {
                object->payload = xqc_realloc(object->payload, object->payload_len);
            }
            DEBUG_PRINTF("==>payload_len:%d\n",(int)object->payload_len);
            msg_ctx->cur_field_idx = 3;
        case 3: //Object Status (i)
            if (object->payload_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &object->status);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                DEBUG_PRINTF("==>status:%d\n", (int) object->status);
            }
            msg_ctx->cur_field_idx = 4;
        case 4: //Object Payload (..)
            if (object->payload_len == 0) {
                *finish = 1;
                break;
            }

            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (object->payload_len - msg_ctx->payload_processed <= buf_len - processed) {
                xqc_memcpy(object->payload + msg_ctx->payload_processed, buf + processed,
                           object->payload_len - msg_ctx->payload_processed);
                processed += object->payload_len - msg_ctx->payload_processed;
                *finish = 1;
            } else {
                xqc_memcpy(object->payload + msg_ctx->payload_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->payload_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * STREAM_HEADER_TRACK Message
 */

void *
xqc_moq_msg_create_track_header(xqc_moq_session_t *session)
{
    xqc_moq_stream_header_track_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_track_header_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_track_header(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t *)msg;
    xqc_free(track_header);
}

xqc_int_t
xqc_moq_msg_track_header_type()
{
    return XQC_MOQ_MSG_STREAM_HEADER_TRACK;
}

void
xqc_moq_msg_track_header_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = track_header_base;
}

void 
xqc_moq_msg_subgroup_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    xqc_moq_subgroup_msg_t *subgroup = (xqc_moq_subgroup_msg_t *)msg_base;
    uint64_t saved_type = subgroup->type;
    *msg_base = subgroup_base;
    if (saved_type != 0) {
        subgroup->type = saved_type;
    } else {
        subgroup->type = XQC_MOQ_SUBGROUP_DEFAULT;
    }
}

void 
xqc_moq_msg_subgroup_object_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = subgroup_object_base;
}

void
xqc_moq_msg_announce_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = announce_base;
}

void
xqc_moq_msg_announce_error_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    msg_base->type = xqc_moq_msg_announce_error_type;
    msg_base->encode_len = xqc_moq_msg_encode_announce_error_len;
    msg_base->encode = xqc_moq_msg_encode_announce_error;
    msg_base->decode = xqc_moq_msg_decode_announce_error;
    msg_base->on_msg = xqc_moq_on_announce_error;
}

void xqc_moq_msg_free_announce_error(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_announce_error_msg_t *announce_error = (xqc_moq_announce_error_msg_t *)msg;
    xqc_free(announce_error->reason_phrase);
    xqc_free(announce_error);
}

void
xqc_moq_msg_fetch_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = fetch_base;
}

void
xqc_moq_msg_subscribe_done_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = subscribe_done_base;
}

xqc_int_t
xqc_moq_msg_encode_track_header_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_STREAM_HEADER_TRACK);
    len += xqc_put_varint_len(track_header->subscribe_id);
    len += xqc_put_varint_len(track_header->track_alias);
    len += xqc_put_varint_len(track_header->send_order);

    return len;
}

xqc_int_t
xqc_moq_msg_encode_track_header(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t *)msg_base;
    if (xqc_moq_msg_encode_track_header_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_STREAM_HEADER_TRACK);
    p = xqc_put_varint(p, track_header->subscribe_id);
    p = xqc_put_varint(p, track_header->track_alias);
    p = xqc_put_varint(p, track_header->send_order);

    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_track_header(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_header->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)track_header->subscribe_id);
            msg_ctx->cur_field_idx = 1;
        case 1: //Track Alias (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_header->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>track_alias:%d\n",(int)track_header->track_alias);
            msg_ctx->cur_field_idx = 2;
        case 2: //Object Send Order (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_header->send_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>send_order:%d\n",(int)track_header->send_order);

            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * MAX_SUBSCRIBE_ID Message
 */

xqc_int_t 
xqc_moq_msg_max_request_id_type()
{
    return XQC_MOQ_MSG_MAX_REQUEST_ID;
}


void xqc_moq_msg_max_request_id_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = max_request_id_base;
}

xqc_int_t xqc_moq_msg_encode_max_request_id_len(xqc_moq_msg_base_t *msg_base)
{
    // TODO
    // xqc_int_t len = 0;
    // len += xqc_put_varint_len(XQC_MOQ_MSG_MAX_SUBSCRIBE_ID);
    // return len;
    return  0;
}

xqc_int_t xqc_moq_msg_encode_max_request_id(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    // if (xqc_moq_msg_encode_max_request_id_len(msg_base) > buf_cap) {
    //     return -XQC_EILLEGAL_FRAME;
    // }

    // uint8_t *p = buf;
    // p = xqc_put_varint(p, XQC_MOQ_MSG_MAX_SUBSCRIBE_ID);
    // return p - buf;
    return 0;
}

xqc_int_t xqc_moq_msg_decode_max_request_id(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 1;
    return 0;
}

// 新增的SUBGROUP_HEADER类型辅助函数实现
xqc_bool_t xqc_moq_subgroup_has_subgroup_id_field(uint64_t type)
{
    // Types 0x14, 0x15, 0x1C, 0x1D have explicit Subgroup ID field
    return (type == XQC_MOQ_SUBGROUP_0x14 || type == XQC_MOQ_SUBGROUP_0x15 ||
            type == XQC_MOQ_SUBGROUP_0x1C || type == XQC_MOQ_SUBGROUP_0x1D);
}

xqc_bool_t xqc_moq_subgroup_has_extensions(uint64_t type)
{
    // Odd types (0x11, 0x13, 0x15, 0x19, 0x1B, 0x1D) have extensions
    return (type == XQC_MOQ_SUBGROUP_0x11 || type == XQC_MOQ_SUBGROUP_0x13 ||
            type == XQC_MOQ_SUBGROUP_0x15 || type == XQC_MOQ_SUBGROUP_0x19 ||
            type == XQC_MOQ_SUBGROUP_0x1B || type == XQC_MOQ_SUBGROUP_0x1D);
}

xqc_bool_t xqc_moq_subgroup_has_end_of_group(uint64_t type)
{
    // Types 0x18-0x1D have end of group
    return (type >= XQC_MOQ_SUBGROUP_0x18 && type <= XQC_MOQ_SUBGROUP_0x1D);
}

uint64_t xqc_moq_subgroup_get_subgroup_id(uint64_t type, uint64_t first_object_id)
{
    if (xqc_moq_subgroup_has_subgroup_id_field(type)) {
        // For types with explicit subgroup ID field, it should be provided separately
        return 0; // This will be overridden by the actual subgroup_id field
    } else if (type == XQC_MOQ_SUBGROUP_0x12 || type == XQC_MOQ_SUBGROUP_0x13 ||
               type == XQC_MOQ_SUBGROUP_0x1A || type == XQC_MOQ_SUBGROUP_0x1B) {
        // Subgroup ID = First Object ID
        return first_object_id;
    } else {
        // Subgroup ID = 0 for types 0x10, 0x11, 0x18, 0x19
        return 0;
    }
}

xqc_bool_t xqc_moq_subgroup_is_valid_type(uint64_t type)
{
    return (type >= XQC_MOQ_SUBGROUP_0x10 && type <= XQC_MOQ_SUBGROUP_0x1D);
}

uint64_t xqc_moq_subgroup_recommend_type(xqc_bool_t need_extensions, 
                                         xqc_bool_t need_end_of_group, 
                                         xqc_bool_t need_explicit_subgroup_id)
{
    // 基于需求推荐最合适的SUBGROUP_HEADER类型
    
    // 如果没有特殊需求，使用默认类型（与之前行为兼容）
    if (!need_extensions && !need_end_of_group && need_explicit_subgroup_id) {
        return XQC_MOQ_SUBGROUP_DEFAULT; // 0x14
    }
    
    if (need_end_of_group) {
        // 需要End of Group标识 (0x18-0x1D)
        if (need_explicit_subgroup_id) {
            return need_extensions ? XQC_MOQ_SUBGROUP_0x1D : XQC_MOQ_SUBGROUP_0x1C;
        } else {
            return need_extensions ? XQC_MOQ_SUBGROUP_0x19 : XQC_MOQ_SUBGROUP_0x18;
        }
    } else {
        // 不需要End of Group标识 (0x10-0x17)
        if (need_explicit_subgroup_id) {
            return need_extensions ? XQC_MOQ_SUBGROUP_0x15 : XQC_MOQ_SUBGROUP_0x14;
        } else {
            return need_extensions ? XQC_MOQ_SUBGROUP_0x11 : XQC_MOQ_SUBGROUP_0x10;
        }
    }
}

void *
xqc_moq_msg_create_max_request_id(xqc_moq_session_t *session)
{
    xqc_moq_max_request_id_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_max_request_id_init_handler(&msg->msg_base, session);
    return msg;
}

xqc_int_t xqc_moq_msg_encode_subgroup_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subgroup_msg_t *subgroup = (xqc_moq_subgroup_msg_t *)msg_base;
    
    // 使用实际的subgroup type而不是固定的XQC_MOQ_SUBGROUP
    uint64_t type = subgroup->type;
    if (!xqc_moq_subgroup_is_valid_type(type)) {
        type = XQC_MOQ_SUBGROUP; // 回退到旧的兼容类型
    }
    
    len += xqc_put_varint_len(type);
    len += xqc_put_varint_len(subgroup->track_alias);
    len += xqc_put_varint_len(subgroup->group_id);
    
    // 只有某些类型才有显式的Subgroup ID字段
    if (xqc_moq_subgroup_has_subgroup_id_field(type)) {
        len += xqc_put_varint_len(subgroup->subgroup_id);
    }
    
    len += XQC_MOQ_PUB_PRIORITY_SIZE; // Publisher Priority
    return len;
}

xqc_int_t xqc_moq_msg_encode_subgroup(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_subgroup_msg_t *subgroup = (xqc_moq_subgroup_msg_t *)msg_base;
    if (xqc_moq_msg_encode_subgroup_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    
    // 使用实际的subgroup type而不是固定的XQC_MOQ_SUBGROUP
    uint64_t type = subgroup->type;
    if (!xqc_moq_subgroup_is_valid_type(type)) {
        type = XQC_MOQ_SUBGROUP; // 回退到旧的兼容类型
    }
    
    p = xqc_put_varint(p, type);
    p = xqc_put_varint(p, subgroup->track_alias);
    p = xqc_put_varint(p, subgroup->group_id);
    
    // 只有某些类型才有显式的Subgroup ID字段
    if (xqc_moq_subgroup_has_subgroup_id_field(type)) {
        p = xqc_put_varint(p, subgroup->subgroup_id);
    }
    
    // Publisher Priority是单字节字段
    *p++ = (uint8_t)subgroup->publish_priority;
    
    return p - buf;
}

xqc_int_t xqc_moq_msg_encode_subgroup_object_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subgroup_object_msg_t *subgroup_object = (xqc_moq_subgroup_object_msg_t *)msg_base;

    len += xqc_put_varint_len(subgroup_object->object_id);
    len += xqc_put_varint_len(subgroup_object->payload_len);
    if(subgroup_object->payload_len > 0) {
        len += subgroup_object->payload_len;
    }
    else {
        len += xqc_put_varint_len(subgroup_object->object_status);
    }
    return len;
}

xqc_int_t xqc_moq_msg_encode_subgroup_object(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subgroup_object_msg_t *subgroup_object = (xqc_moq_subgroup_object_msg_t *)msg_base;
    if(xqc_moq_msg_encode_subgroup_object_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, subgroup_object->object_id);
    p = xqc_put_varint(p, subgroup_object->payload_len);
    if(subgroup_object->payload_len > 0) {
        xqc_memcpy(p, subgroup_object->payload, subgroup_object->payload_len);
        p += subgroup_object->payload_len;
    }
    else {
        p = xqc_put_varint(p, subgroup_object->object_status);
    }
    return p - buf;
}

xqc_int_t xqc_moq_msg_encode_subgroup_object_ext_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subgroup_object_msg_ext_t *subgroup_object_ext = (xqc_moq_subgroup_object_msg_ext_t *)msg_base;

    len += xqc_put_varint_len(subgroup_object_ext->object_id);
    len += xqc_put_varint_len(subgroup_object_ext->extension_header_len);
    if(subgroup_object_ext->extension_header_len > 0) {
        len += subgroup_object_ext->extension_header_len;
    }
    len += xqc_put_varint_len(subgroup_object_ext->payload_len);
    if(subgroup_object_ext->payload_len > 0) {
        len += subgroup_object_ext->payload_len;
    }
    else {
        len += xqc_put_varint_len(subgroup_object_ext->object_status);
    }
    return len;
}

xqc_int_t xqc_moq_msg_encode_subgroup_object_ext(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subgroup_object_msg_ext_t *subgroup_object_ext = (xqc_moq_subgroup_object_msg_ext_t *)msg_base;
    if(xqc_moq_msg_encode_subgroup_object_ext_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, subgroup_object_ext->object_id);
    p = xqc_put_varint(p, subgroup_object_ext->extension_header_len);
    if(subgroup_object_ext->extension_header_len > 0) {
        xqc_memcpy(p, subgroup_object_ext->extension_header, subgroup_object_ext->extension_header_len);
        p += subgroup_object_ext->extension_header_len;
    }

    p = xqc_put_varint(p, subgroup_object_ext->payload_len);
    if(subgroup_object_ext->payload_len > 0) {
        xqc_memcpy(p, subgroup_object_ext->payload, subgroup_object_ext->payload_len);
        p += subgroup_object_ext->payload_len;
    }
    else {
        p = xqc_put_varint(p, subgroup_object_ext->object_status);
    }
    return p - buf;
}

xqc_int_t xqc_moq_msg_encode_announce_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_announce_msg_t *announce_msg = (xqc_moq_announce_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_ANNOUNCE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE; // Length field
    len += xqc_put_varint_len(announce_msg->request_id);
    len += xqc_put_varint_len(announce_msg->track_namespace->track_namespace_num);
    for(size_t i = 0; i<announce_msg->track_namespace->track_namespace_num;i++)
    {
        len += xqc_put_varint_len(announce_msg->track_namespace->track_namespace_len[i]);
        len += announce_msg->track_namespace->track_namespace_len[i];
    }
    len += xqc_put_varint_len(announce_msg->params_num);
    len += xqc_moq_msg_encode_params_len(announce_msg->params, announce_msg->params_num);
    printf("encode announce len: %d\n", len);
    return len;
}

xqc_int_t xqc_moq_msg_encode_announce_error_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_announce_error_msg_t *announce_error = (xqc_moq_announce_error_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_ANNOUNCE_ERROR);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE; // Length field
    len += xqc_put_varint_len(announce_error->request_id);
    len += xqc_put_varint_len(announce_error->error_code);
    len += xqc_put_varint_len(announce_error->reason_phrase_len);
    len += announce_error->reason_phrase_len;
    return len;
}

xqc_int_t xqc_moq_msg_encode_announce(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_announce_msg_t *announce_msg = (xqc_moq_announce_msg_t *)msg_base;
    uint64_t length = xqc_moq_msg_encode_announce_len(msg_base) ; 
    if(length > buf_cap){
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_ANNOUNCE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_ANNOUNCE);
    p = xqc_moq_put_varint_length(p,length);
    p = xqc_put_varint(p, announce_msg->request_id);
    p = xqc_put_varint(p, announce_msg->track_namespace->track_namespace_num);
    for(size_t i = 0; i < announce_msg->track_namespace->track_namespace_num; i++){
        p = xqc_put_varint(p, announce_msg->track_namespace->track_namespace_len[i]);
        xqc_memcpy(p, announce_msg->track_namespace->track_namespace[i], announce_msg->track_namespace->track_namespace_len[i]);
        p += announce_msg->track_namespace->track_namespace_len[i];
    }
    p = xqc_put_varint(p, announce_msg->params_num);
    ret = xqc_moq_msg_encode_params(announce_msg->params, announce_msg->params_num, p, buf_cap - (p - buf));

    if(ret < 0){
        return ret;
    }
    p += ret;
    

    return p - buf;
}

xqc_int_t xqc_moq_msg_encode_announce_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_announce_error_msg_t *announce_error = (xqc_moq_announce_error_msg_t*)msg_base;
    uint64_t len = xqc_moq_msg_encode_announce_error_len(msg_base);
    if (len > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    len = len - xqc_put_varint_len(XQC_MOQ_MSG_ANNOUNCE_ERROR) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_ANNOUNCE_ERROR);
    p = xqc_moq_put_varint_length(p, len);
    p = xqc_put_varint(p, announce_error->request_id);
    p = xqc_put_varint(p, announce_error->error_code);
    p = xqc_put_varint(p, announce_error->reason_phrase_len);
        xqc_memcpy(p, announce_error->reason_phrase, announce_error->reason_phrase_len);
        p += announce_error->reason_phrase_len;

    return p - buf;
}

void
xqc_moq_msg_free_max_request_id(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_max_request_id_msg_t *max_request_id = (xqc_moq_max_request_id_msg_t *)msg;
    xqc_free(max_request_id);
}

void *
xqc_moq_msg_create_requests_blocked(xqc_moq_session_t *session)
{
    xqc_moq_requests_blocked_msg_t *requests_blocked = xqc_calloc(1, sizeof(xqc_moq_requests_blocked_msg_t));
    if (requests_blocked == NULL) {
        return NULL;
    }
    
    requests_blocked->msg_base = requests_blocked_base;
    xqc_moq_msg_requests_blocked_init_handler(&requests_blocked->msg_base, session);
    return requests_blocked;
}

void
xqc_moq_msg_free_requests_blocked(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_requests_blocked_msg_t *requests_blocked = (xqc_moq_requests_blocked_msg_t *)msg;
    xqc_free(requests_blocked);
}

xqc_int_t
xqc_moq_msg_requests_blocked_type()
{
    return XQC_MOQ_MSG_REQUESTS_BLOCKED;
}

void
xqc_moq_msg_requests_blocked_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = requests_blocked_base;
}

xqc_int_t
xqc_moq_msg_encode_requests_blocked_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_requests_blocked_msg_t *requests_blocked = (xqc_moq_requests_blocked_msg_t *)msg_base;
    xqc_int_t len = 0;

    len += xqc_put_varint_len(XQC_MOQ_MSG_REQUESTS_BLOCKED);
    len += xqc_put_varint_len(requests_blocked->length);
    len += xqc_put_varint_len(requests_blocked->max_request_id);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_requests_blocked(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_requests_blocked_msg_t *requests_blocked = (xqc_moq_requests_blocked_msg_t *)msg_base;
    uint8_t *p = buf;
    
    p = xqc_put_varint(p, XQC_MOQ_MSG_REQUESTS_BLOCKED);
    if (p == NULL) {
        return -XQC_EWRITE_PKT;
    }
    
    p = xqc_put_varint(p, requests_blocked->length);
    if (p == NULL) {
        return -XQC_EWRITE_PKT;
    }
    
    p = xqc_put_varint(p, requests_blocked->max_request_id);
    if (p == NULL) {
        return -XQC_EWRITE_PKT;
    }
    
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_requests_blocked(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_requests_blocked_msg_t *requests_blocked = (xqc_moq_requests_blocked_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &requests_blocked->length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>length:%d\n",(int)requests_blocked->length);
            msg_ctx->cur_field_idx = 1;
        case 1: // max_request_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &requests_blocked->max_request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>max_request_id:%d\n",(int)requests_blocked->max_request_id);
            msg_ctx->cur_field_idx = 2;
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

void
xqc_moq_on_requests_blocked(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_requests_blocked_msg_t *requests_blocked = (xqc_moq_requests_blocked_msg_t *)msg_base;
    
    xqc_log(session->log, XQC_LOG_DEBUG, "|moq|received REQUESTS_BLOCKED|max_request_id:%ui|", 
            requests_blocked->max_request_id);
    
    // TODO: 根据需要处理 REQUESTS_BLOCKED 消息的逻辑
}

xqc_int_t
xqc_moq_write_subgroup(xqc_moq_session_t *session, xqc_moq_subgroup_msg_t *subgroup,xqc_int_t subgroup_object_num,
    xqc_moq_subgroup_object_msg_t **subgroup_object)
{
    xqc_int_t ret = 0;
    xqc_moq_stream_t *stream;
    
    stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if(stream==NULL)
    {
        DEBUG_PRINTF("xqc_moq_stream_create_with_transport failed\n");
        return -1;
    }
    stream->write_stream_fin = 0;

    ret = xqc_moq_write_subgroup_msg(session, stream, subgroup);
    if(ret < 0){
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_stream_header_subgroup_msg failed|ret:%d|", ret);
        return ret;
    }



    for(xqc_int_t i = 0; i < subgroup_object_num; i++){
        if(i == subgroup_object_num - 1){ 
            stream->write_stream_fin = 1; 
        }
        else {
            stream->write_stream_fin = 0;
        }
        ret = xqc_moq_write_subgroup_object_msg(session, stream, subgroup_object[i]);
        if(ret < 0){
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_subgroup_object_msg failed|ret:%d|", ret);
            return ret;
        }
    }
    return ret ; 
}

xqc_int_t
xqc_moq_write_announce(xqc_moq_session_t *session, xqc_moq_announce_msg_t *announce_msg)
{
    xqc_int_t ret = 0; 
    if(session->ctl_stream==NULL)
    {
        DEBUG_PRINTF("xqc_moq_stream_create_with_transport failed\n");
        return -1;
    }

    ret = xqc_moq_write_announce_msg(session, session->ctl_stream, announce_msg);
    if(ret < 0){
        DEBUG_PRINTF("xqc_moq_write_announce_msg failed\n");
        return ret;
    }
    return ret;
}

xqc_int_t 
xqc_moq_write_announce_ok(xqc_moq_session_t *session, xqc_moq_announce_ok_msg_t *announce_ok)
{
    xqc_int_t ret = 0;
    if(session->ctl_stream==NULL)
    {
        DEBUG_PRINTF("xqc_moq_stream_create_with_transport failed\n");
        return -1;
    }

    ret = xqc_moq_write_announce_ok_msg(session, session->ctl_stream, announce_ok);
    if(ret < 0){
        DEBUG_PRINTF("xqc_moq_write_announce_ok_msg failed\n");
        return ret;
    }
    return ret;
}

xqc_int_t 
xqc_moq_write_subscribe_namespace(xqc_moq_session_t *session, xqc_moq_subscribe_namespace_msg_t *subscribe_namespace)
{
    xqc_int_t ret = 0;
    if(session->ctl_stream==NULL)
    {
        DEBUG_PRINTF("xqc_moq_stream_create_with_transport failed\n");
        return -1;
    }

    ret = xqc_moq_msg_write_subscribe_namespace(session, session->ctl_stream, subscribe_namespace);
    if(ret < 0){
        DEBUG_PRINTF("xqc_moq_msg_write_subscribe_namespace failed\n");
        return ret;
    }
    return ret;
}

xqc_int_t
xqc_moq_write_publish_namespace(xqc_moq_session_t *session, xqc_moq_publish_namespace_msg_t *publish_ns)
{
    if (session->ctl_stream == NULL) {
        return -XQC_EPARAM;
    }
    return xqc_moq_msg_write_publish_namespace(session, session->ctl_stream, publish_ns);
}

xqc_int_t
xqc_moq_write_publish_namespace_done(xqc_moq_session_t *session, xqc_moq_publish_namespace_done_msg_t *publish_ns_done)
{
    if (session->ctl_stream == NULL) {
        return -XQC_EPARAM;
    }
    return xqc_moq_msg_write_publish_namespace_done(session, session->ctl_stream, publish_ns_done);
}

xqc_int_t
xqc_moq_write_unsubscribe_namespace(xqc_moq_session_t *session, xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace)
{
    xqc_int_t ret = 0;
    if(session->ctl_stream==NULL)
    {
        DEBUG_PRINTF("xqc_moq_stream_create_with_transport failed\n");
        return -1;
    }

    ret = xqc_moq_write_unsubscribe_namespace_msg(session, unsubscribe_namespace);
    if(ret < 0){
        DEBUG_PRINTF("xqc_moq_msg_write_unsubscribe_namespace failed\n");
        return ret;
    }
    return ret;
}

xqc_int_t
xqc_moq_write_subscribe_namespace_ok(xqc_moq_session_t *session, xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok)
{
    xqc_int_t ret = 0;
    if(session->ctl_stream==NULL)
    {
        DEBUG_PRINTF("xqc_moq_stream_create_with_transport failed\n");
        return -1;
    }
    ret = xqc_moq_write_subscribe_namespace_ok_msg(session, session->ctl_stream, subscribe_namespace_ok);
    if(ret < 0){
        DEBUG_PRINTF("xqc_moq_msg_write_subscribe_namespace_ok failed\n");
        return ret;
    }
    return ret;
}

xqc_int_t
xqc_moq_msg_decode_announce(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, 
    xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_moq_announce_msg_t *announce_msg = (xqc_moq_announce_msg_t *)msg_base;
    uint64_t element_len = 0;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: // request_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &announce_msg->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
            msg_ctx->cur_array_idx = 0;
        case 2: // track_namespace (tuple)
            if(announce_msg->track_namespace == NULL)
            {
                announce_msg->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
                announce_msg->track_namespace->track_namespace_num = 0;
                announce_msg->track_namespace->track_namespace = NULL;
                announce_msg->track_namespace->track_namespace_len = NULL;
            }
            if(announce_msg->track_namespace->track_namespace_num == 0)
            {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &announce_msg->track_namespace->track_namespace_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
                announce_msg->track_namespace->track_namespace_len = xqc_calloc(announce_msg->track_namespace->track_namespace_num, sizeof(uint64_t));
                announce_msg->track_namespace->track_namespace = xqc_calloc(announce_msg->track_namespace->track_namespace_num, sizeof(char*));
            }
            for(; msg_ctx->cur_array_idx < announce_msg->track_namespace->track_namespace_num ; msg_ctx->cur_array_idx++)
            {
                if (announce_msg->track_namespace->track_namespace_len[msg_ctx->cur_array_idx] == 0) {
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &announce_msg->track_namespace->track_namespace_len[msg_ctx->cur_array_idx]);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    DEBUG_PRINTF("==>namespace_len:%d\n",(int)announce_msg->track_namespace->track_namespace_len[msg_ctx->cur_array_idx]);
                    processed += ret;
                }
                if (announce_msg->track_namespace->track_namespace[msg_ctx->cur_array_idx] == NULL) {
                    if (announce_msg->track_namespace->track_namespace_len[msg_ctx->cur_array_idx] > XQC_MOQ_MAX_NAME_LEN) {
                        return -XQC_ELIMIT;
                    }
                    announce_msg->track_namespace->track_namespace[msg_ctx->cur_array_idx] = xqc_calloc(1, announce_msg->track_namespace->track_namespace_len[msg_ctx->cur_array_idx]+1);
                }
                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                } else if (announce_msg->track_namespace->track_namespace_len[msg_ctx->cur_array_idx] - msg_ctx->str_processed <= buf_len - processed) {
                    xqc_memcpy(announce_msg->track_namespace->track_namespace[msg_ctx->cur_array_idx] + msg_ctx->str_processed, buf + processed,
                            announce_msg->track_namespace->track_namespace_len[msg_ctx->cur_array_idx] - msg_ctx->str_processed);
                    processed += announce_msg->track_namespace->track_namespace_len[msg_ctx->cur_array_idx] - msg_ctx->str_processed;
                    msg_ctx->str_processed = 0; //track_namespace finish
                } else {
                    xqc_memcpy(announce_msg->track_namespace->track_namespace[msg_ctx->cur_array_idx] + msg_ctx->str_processed, buf + processed,
                            buf_len - processed);
                    msg_ctx->str_processed += buf_len - processed;
                    processed += buf_len - processed;
                    *wait_more_data = 1;
                    break;
                }
            }
            msg_ctx->cur_field_idx = 3;
        case 3: // params_num
            ret = xqc_vint_read(buf + processed, buf + buf_len, &announce_msg->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 4;
        case 4: // params
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                 announce_msg->params, announce_msg->params_num,
                                 finish, wait_more_data);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

xqc_int_t 
xqc_moq_msg_decode_announce_ok(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, 
    xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_moq_announce_ok_msg_t *announce_ok = (xqc_moq_announce_ok_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: // request_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &announce_ok->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

void 
xqc_moq_on_announce_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
    xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_announce_ok_msg_t *announce_ok = (xqc_moq_announce_ok_msg_t *)msg_base;
    xqc_log(session->log, XQC_LOG_INFO, "|xqc_moq_on_announce_ok|request_id:%llu|",
            announce_ok->request_id);
    if(session->session_callbacks.on_announce_ok){
        session->session_callbacks.on_announce_ok(session->user_session, announce_ok);
    }
    else {
        xqc_log(session->log, XQC_LOG_WARN, "|xqc_moq_on_announce_ok|no callback|");
    }
    return; 
}

void
xqc_moq_on_announce_error(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
    xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_announce_error_msg_t *announce_error = (xqc_moq_announce_error_msg_t *)msg_base;
    xqc_log(session->log, XQC_LOG_INFO, "|xqc_moq_on_announce_error|request_id:%llu|error_code:%llu|reason:%s|",
            announce_error->request_id, announce_error->error_code, announce_error->reason_phrase);
    if(session->session_callbacks.on_announce_error){
        session->session_callbacks.on_announce_error(session->user_session, announce_error);
    }
    else {
        xqc_log(session->log, XQC_LOG_WARN, "|xqc_moq_on_announce_error|no callback|");
    }
    return; 
}

xqc_int_t xqc_moq_msg_decode_announce_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, 
    xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_moq_announce_error_msg_t *announce_error = (xqc_moq_announce_error_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: // request_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &announce_error->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: // error_code
            ret = xqc_vint_read(buf + processed, buf + buf_len, &announce_error->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 3;
        case 3: // reason_phrase_len
            ret = xqc_vint_read(buf + processed, buf + buf_len, &announce_error->reason_phrase_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (announce_error->reason_phrase_len > XQC_MOQ_MAX_REASON_LEN) {
                return -XQC_ELIMIT;
            }
            announce_error->reason_phrase = xqc_calloc(1, announce_error->reason_phrase_len + 1);
            msg_ctx->cur_field_idx = 4;
        case 4: // reason_phrase
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (announce_error->reason_phrase_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(announce_error->reason_phrase + msg_ctx->str_processed, buf + processed,
                        announce_error->reason_phrase_len - msg_ctx->str_processed);
                processed += announce_error->reason_phrase_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0;
                *finish = 1;
            } else {
                xqc_memcpy(announce_error->reason_phrase + msg_ctx->str_processed, buf + processed,
                        buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

void *
xqc_moq_msg_create_unsubscribe(xqc_moq_session_t *session)
{
    xqc_moq_unsubscribe_msg_t *unsubscribe_msg = xqc_calloc(1, sizeof(xqc_moq_unsubscribe_msg_t));
    xqc_moq_msg_unsubscribe_init_handler(&unsubscribe_msg->msg_base, session);
    return unsubscribe_msg;
}

void *
xqc_moq_msg_create_track_status(xqc_moq_session_t *session)
{
    xqc_moq_track_status_msg_t *track_status_msg = xqc_calloc(1, sizeof(xqc_moq_track_status_msg_t));
    xqc_moq_msg_track_status_init_handler(&track_status_msg->msg_base, session);
    return track_status_msg;
}

void *
xqc_moq_msg_create_track_status_ok(xqc_moq_session_t *session)
{
    xqc_moq_track_status_ok_msg_t *track_status_ok = xqc_calloc(1, sizeof(xqc_moq_track_status_ok_msg_t));
    xqc_moq_msg_track_status_ok_init_handler(&track_status_ok->msg_base, session);
    return track_status_ok;
}

void *
xqc_moq_msg_create_track_status_error(xqc_moq_session_t *session)
{
    xqc_moq_track_status_error_msg_t *track_status_error = xqc_calloc(1, sizeof(xqc_moq_track_status_error_msg_t));
    xqc_moq_msg_track_status_error_init_handler(&track_status_error->msg_base, session);
    return track_status_error;
}

void
xqc_moq_msg_free_track_status(void *msg)
{
    xqc_moq_track_status_msg_t *track_status_msg = (xqc_moq_track_status_msg_t *)msg;
    xqc_free(track_status_msg);
}

void
xqc_moq_msg_free_track_status_ok(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_track_status_ok_msg_t *track_status_ok = (xqc_moq_track_status_ok_msg_t *)msg;
    if (track_status_ok->params_num > 0 && track_status_ok->params != NULL) {
        xqc_moq_msg_free_params(track_status_ok->params, track_status_ok->params_num);
    }
    xqc_free(track_status_ok);
}

void
xqc_moq_msg_free_track_status_error(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_track_status_error_msg_t *track_status_error = (xqc_moq_track_status_error_msg_t *)msg;
    if (track_status_error->error_reason != NULL) {
        xqc_free(track_status_error->error_reason);
    }
    xqc_free(track_status_error);
}

void 
xqc_moq_msg_unsubscribe_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = unsubscribe_base;
}

xqc_int_t 
xqc_moq_msg_decode_unsubscribe(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, 
    xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0 ;
    uint64_t subscribe_id = 0;
    xqc_moq_unsubscribe_msg_t *unsubscribe_msg = (xqc_moq_unsubscribe_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: // subscribe_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            unsubscribe_msg->subscribe_id = subscribe_id;
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

void
xqc_moq_on_unsubscribe(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
    xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_unsubscribe_msg_t *unsubscribe_msg = (xqc_moq_unsubscribe_msg_t *)msg_base;
    xqc_moq_subscribe_t *subscribe = xqc_moq_find_subscribe(session, unsubscribe_msg->subscribe_id, 0);
    // TODO
    if(subscribe == NULL){
        xqc_log(session->log, XQC_LOG_WARN, "|xqc_moq_on_unsubscribe|subscribe not found|");
        return;
    }
    if(session->session_callbacks.on_unsubscribe){
        session->session_callbacks.on_unsubscribe(session->user_session, unsubscribe_msg);
    }
    else {
        xqc_log(session->log, XQC_LOG_WARN, "|xqc_moq_on_unsubscribe|no callback|");
    }
}

void 
xqc_moq_msg_free_unsubscribe(void *msg)
{
    xqc_moq_unsubscribe_msg_t *unsubscribe_msg = (xqc_moq_unsubscribe_msg_t *)msg;
    xqc_free(unsubscribe_msg);
}

void*
xqc_moq_msg_create_subgroup(xqc_moq_session_t *session)
{
    xqc_moq_subgroup_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subgroup_init_handler(&msg->msg_base, session);
    return msg;
}

void 
xqc_moq_msg_free_subgroup(void *msg)
{
    xqc_moq_subgroup_msg_t *subgroup_msg = (xqc_moq_subgroup_msg_t *)msg;
    xqc_free(subgroup_msg);
}

void*
xqc_moq_msg_create_subgroup_object(xqc_moq_session_t *session)
{
    xqc_moq_subgroup_object_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subgroup_object_init_handler(&msg->msg_base, session);
    return msg;
}

void*
xqc_moq_msg_create_subgroup_object_ext(xqc_moq_session_t *session)
{
    xqc_moq_subgroup_object_msg_ext_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subgroup_object_ext_init_handler(&msg->msg_base, session);
    return msg;
}

void 
xqc_moq_msg_free_subgroup_object(void *msg)
{
    xqc_moq_subgroup_object_msg_t *subgroup_object_msg = (xqc_moq_subgroup_object_msg_t *)msg;
    if (subgroup_object_msg == NULL) {
        return;
    }
    if (subgroup_object_msg->extension_header) {
        xqc_free(subgroup_object_msg->extension_header);
        subgroup_object_msg->extension_header = NULL;
    }
    if (subgroup_object_msg->payload) {
        xqc_free(subgroup_object_msg->payload);
        subgroup_object_msg->payload = NULL;
    }
    xqc_free(subgroup_object_msg);
}

void 
xqc_moq_msg_free_subgroup_object_ext(void *msg)
{
    xqc_moq_subgroup_object_msg_ext_t *subgroup_object_msg = (xqc_moq_subgroup_object_msg_ext_t *)msg;
    if (subgroup_object_msg == NULL) {
        return;
    }
    if (subgroup_object_msg->extension_header) {
        xqc_free(subgroup_object_msg->extension_header);
        subgroup_object_msg->extension_header = NULL;
    }
    if (subgroup_object_msg->payload) {
        xqc_free(subgroup_object_msg->payload);
        subgroup_object_msg->payload = NULL;
    }
    xqc_free(subgroup_object_msg);
}


xqc_int_t 
xqc_moq_msg_decode_subgroup(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, 
    xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t subscribe_id = 0;
    xqc_moq_subgroup_msg_t *subgroup_msg = (xqc_moq_subgroup_msg_t *)msg_base;
    
    // 获取实际的subgroup type，这在stream解析阶段已经读取并设置在msg_ctx中
    uint64_t type = msg_ctx->cur_msg_type;
    if (!xqc_moq_subgroup_is_valid_type(type)) {
        type = XQC_MOQ_SUBGROUP; // 回退到旧的兼容类型
    }
    
    // 设置subgroup_msg中的type字段
    subgroup_msg->type = type;
    
    switch (msg_ctx->cur_field_idx) {
        case 0: // track alias
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subgroup_msg->track_alias);
            if(ret < 0){
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //group id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subgroup_msg->group_id);
            if(ret < 0){
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            // 根据类型决定下一个字段
            if (xqc_moq_subgroup_has_subgroup_id_field(type)) {
                msg_ctx->cur_field_idx = 2; // 有显式subgroup ID字段
            } else {
                msg_ctx->cur_field_idx = 3; // 直接跳到publisher priority
                // 根据类型设置隐式的subgroup ID
                subgroup_msg->subgroup_id = xqc_moq_subgroup_get_subgroup_id(type, 0); // first_object_id将在后续设置
            }
        case 2: // subgroup id (仅在特定类型中存在)
            if (xqc_moq_subgroup_has_subgroup_id_field(type)) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &subgroup_msg->subgroup_id);
                if(ret < 0){    
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
            }
            msg_ctx->cur_field_idx = 3;
        case 3: // publish priority (单字节)
            if (buf_len - processed < 1) {
                *wait_more_data = 1;
                break;
            }
            subgroup_msg->publish_priority = buf[processed];
            processed += 1;
            
            subgroup_msg->subgroup_id_present = xqc_moq_subgroup_has_subgroup_id_field(type);
            subgroup_msg->extensions_present = xqc_moq_subgroup_has_extensions(type);
            subgroup_msg->end_of_group = xqc_moq_subgroup_has_end_of_group(type);
            
            *finish = 1;
            break;

        default:
            return -XQC_EILLEGAL_FRAME;
    }
    
    return processed;
}


xqc_int_t
xqc_moq_msg_decode_subscribe_namespace_ok(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, 
    xqc_int_t *wait_more_data)
{
    printf("xqc_moq_msg_decode_subscribe_namespace_ok\n");
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok = (xqc_moq_subscribe_namespace_ok_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: // request_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_namespace_ok->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

void 
xqc_moq_on_subscribe_namespace_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
    xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok = (xqc_moq_subscribe_namespace_ok_msg_t *)msg_base;
    xqc_log(session->log, XQC_LOG_INFO, "|xqc_moq_on_subscribe_namespace_ok|request_id:%llu|",
            subscribe_namespace_ok->request_id);
    if(session->session_callbacks.on_subscribe_namespace_ok){
        session->session_callbacks.on_subscribe_namespace_ok(session->user_session, subscribe_namespace_ok);
    }
    else {
        xqc_log(session->log, XQC_LOG_WARN, "|xqc_moq_on_subscribe_namespace_ok|no callback|");
    }
    return; 
}

xqc_int_t
xqc_moq_msg_encode_subscribe_done_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_done_msg_t *subscribe_done_msg = (xqc_moq_subscribe_done_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_DONE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe_done_msg->subscribe_id);
    len += xqc_put_varint_len(subscribe_done_msg->status_code);
    len += xqc_put_varint_len(subscribe_done_msg->stream_count);
    len += xqc_put_varint_len(subscribe_done_msg->reason_len);
    len += subscribe_done_msg->reason_len;
    return len;
}

xqc_int_t 
xqc_moq_msg_encode_subscribe_done(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_done_msg_t *subscribe_done_msg = (xqc_moq_subscribe_done_msg_t *)msg_base;
    uint64_t length = xqc_moq_msg_encode_subscribe_done_len(msg_base);
    if(length > buf_cap){
        return -XQC_EILLEGAL_FRAME;
    }
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_DONE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_DONE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, subscribe_done_msg->subscribe_id);
    p = xqc_put_varint(p, subscribe_done_msg->status_code);
    p = xqc_put_varint(p, subscribe_done_msg->stream_count);
    p = xqc_put_varint(p, subscribe_done_msg->reason_len);
    xqc_memcpy(p, subscribe_done_msg->reason, subscribe_done_msg->reason_len);
    p += subscribe_done_msg->reason_len;
    return p - buf;
}

xqc_int_t 
xqc_moq_msg_decode_subscribe_done(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, 
    xqc_int_t *wait_more_data)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_moq_subscribe_done_msg_t *subscribe_done_msg = (xqc_moq_subscribe_done_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: // subscribe_id(i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_done_msg->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: // status_code(i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe_done_msg->status_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 3;
        case 3: // stream_count(i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_done_msg->stream_count);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 4;
        case 4: // reason_len(i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_done_msg->reason_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 5;
        case 5: // reason(..)
            subscribe_done_msg->reason = xqc_calloc(subscribe_done_msg->reason_len, sizeof(char));
            memcpy(subscribe_done_msg->reason, buf + processed, subscribe_done_msg->reason_len);
            processed += subscribe_done_msg->reason_len;
            *finish = 1;
            break;

        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

void
xqc_moq_on_subscribe_done(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_done_msg_t *subscribe_done = (xqc_moq_subscribe_done_msg_t *)msg_base;
    xqc_log(session->log, XQC_LOG_INFO, "|xqc_moq_on_subscribe_done|subscribe_id:%ui|status_code:%ui|stream_count:%ui|reason:%s|",
            subscribe_done->subscribe_id, subscribe_done->status_code, subscribe_done->stream_count, subscribe_done->reason);

    xqc_moq_cancel_subscribe(session, subscribe_done->subscribe_id, 0);
    // TODO more tests are needed
    return ;
}

void *
xqc_moq_msg_create_subscribe_done(xqc_moq_session_t *session)
{
    xqc_moq_subscribe_done_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_done_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_subscribe_done(void *msg)
{
    xqc_free(msg);
}

void 
xqc_moq_msg_track_status_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = track_status_base;
}

void
xqc_moq_msg_track_status_ok_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = track_status_ok_base;
}

void
xqc_moq_msg_track_status_error_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = track_status_error_base;
}


xqc_int_t 
xqc_moq_msg_decode_track_status_request(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    return 0; // TODO
}


void *
xqc_moq_msg_create_announce(xqc_moq_session_t *session)
{
    xqc_moq_announce_msg_t *announce_msg = xqc_calloc(1, sizeof(xqc_moq_announce_msg_t));
    announce_msg->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
    xqc_moq_msg_announce_init_handler(&announce_msg->msg_base, session);
    return announce_msg;
}

void *
xqc_moq_msg_create_announce_error(xqc_moq_session_t *session)
{
    xqc_moq_announce_error_msg_t *announce_error = xqc_calloc(1, sizeof(xqc_moq_announce_error_msg_t));
    xqc_moq_msg_announce_error_init_handler(&announce_error->msg_base, session);
    return announce_error;
}

void 
xqc_moq_msg_free_announce(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_announce_msg_t *announce_msg = (xqc_moq_announce_msg_t *)msg;
    xqc_moq_msg_free_track_namespace(announce_msg->track_namespace);
    xqc_free(announce_msg->params);
    xqc_free(announce_msg);
}

void
xqc_moq_msg_goaway_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = goaway_base;
}

void *
xqc_moq_msg_create_goaway(xqc_moq_session_t *session)
{
    xqc_moq_goaway_msg_t *msg = xqc_calloc(1, sizeof(xqc_moq_goaway_msg_t));
    xqc_moq_msg_goaway_init_handler(&msg->msg_base, session);
    return msg;
}

xqc_int_t
xqc_moq_msg_goaway_type()
{
    return XQC_MOQ_MSG_GOAWAY;
}

xqc_int_t
xqc_moq_msg_encode_goaway_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_goaway_msg_t *goaway_msg = (xqc_moq_goaway_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_GOAWAY);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(goaway_msg->new_URI_len);
    len += goaway_msg->new_URI_len;
    return len;
}

uint8_t *
xqc_put_varint_for_length(uint8_t *p, uint64_t n)
{
    uint8_t *rv;
    if (n < 64) {
        *p++ = (uint8_t)n;
        *p++ = 0;
        return p;
    }

    if (n < 16384) {
        rv = xqc_put_uint16be(p, (uint16_t)n);
        *p |= 0x40;
        return rv;
    }

    if (n < 1073741824) {
        rv = xqc_put_uint32be(p, (uint32_t)n);
        *p |= 0x80;
        return rv;
    }

    if (n >= 4611686018427387904ULL) {
        return NULL;
    }

    rv = xqc_put_uint64be(p, n);
    *p |= 0xc0;
    return rv;
}


xqc_int_t
xqc_moq_msg_encode_goaway(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_goaway_msg_t *goaway_msg = (xqc_moq_goaway_msg_t *)msg_base;
    uint64_t length = xqc_moq_msg_encode_goaway_len(msg_base);
    if(length > buf_cap){
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_GOAWAY) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_GOAWAY);
    p = xqc_put_varint_for_length(p, length);
    p = xqc_put_varint(p, goaway_msg->new_URI_len);
    if(goaway_msg->new_URI_len > 0){
        xqc_memcpy(p, goaway_msg->new_URI, goaway_msg->new_URI_len);
        p += goaway_msg->new_URI_len;
    }
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_goaway(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t length_expected = 0;
    xqc_moq_goaway_msg_t *goaway_msg = (xqc_moq_goaway_msg_t *)msg_base;
    switch(msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: // new_URI_len
            ret = xqc_vint_read(buf + processed, buf + buf_len, &goaway_msg->new_URI_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: // new_URI(..)
            goaway_msg->new_URI = xqc_calloc(goaway_msg->new_URI_len, sizeof(char));
            memcpy(goaway_msg->new_URI, buf + processed, goaway_msg->new_URI_len);
            processed += goaway_msg->new_URI_len;
            *finish = 1;
            break;

        default:
                return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

void
xqc_moq_on_goaway(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_goaway_msg_t *goaway_msg = (xqc_moq_goaway_msg_t *)msg_base;
    if(goaway_msg->new_URI_len > 0){
        DEBUG_PRINTF("xqc_moq_on_goaway|new_URI:%s\n", goaway_msg->new_URI);
    }
    if(session->session_callbacks.on_goaway != NULL){
        session->session_callbacks.on_goaway(session->user_session, goaway_msg);
    }
}

void
xqc_moq_msg_free_goaway(void *msg)
{
    xqc_moq_goaway_msg_t *goaway = (xqc_moq_goaway_msg_t *)msg;
    xqc_free(goaway->new_URI);
    xqc_free(goaway);
}

xqc_int_t
xqc_moq_write_goaway(xqc_moq_session_t *session, uint64_t new_URI_len, char *new_URI)
{
    DEBUG_PRINTF("xqc_moq_write_goaway|new_URI_len:%d|new_URI:%s\n", new_URI_len, new_URI);
    if(session == NULL) {
        DEBUG_PRINTF("xqc_moq_write_goaway|session is NULL\n");
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_int_t ret = 0;
    xqc_moq_goaway_msg_t *go_away = xqc_calloc(1, sizeof(xqc_moq_goaway_msg_t));
    go_away->new_URI_len = new_URI_len;
    go_away->new_URI = xqc_calloc(new_URI_len, sizeof(char));
    memcpy(go_away->new_URI, new_URI, new_URI_len);
    ret = xqc_moq_msg_write_goaway(session, session->ctl_stream, go_away);
    if(go_away->new_URI != NULL){
        xqc_free(go_away->new_URI);
    }
    xqc_free(go_away);
    return ret;
}

xqc_int_t
xqc_moq_msg_track_status_type()
{
    return XQC_MOQ_MSG_TRACK_STATUS;
}

xqc_int_t
xqc_moq_msg_track_status_ok_type()
{
    return XQC_MOQ_MSG_TRACK_STATUS_OK;
}

xqc_int_t
xqc_moq_msg_track_status_error_type()
{
    return XQC_MOQ_MSG_TRACK_STATUS_ERROR;
}

xqc_int_t
xqc_moq_msg_encode_track_status_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_track_status_msg_t *track_status_msg = (xqc_moq_track_status_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_TRACK_STATUS);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(track_status_msg->request_id);
    len += xqc_put_varint_len(track_status_msg->track_namespace->track_namespace_num);
    for(size_t idx = 0; idx < track_status_msg->track_namespace->track_namespace_num; idx++) {
        len += xqc_put_varint_len(track_status_msg->track_namespace->track_namespace_len[idx]);
        len += track_status_msg->track_namespace->track_namespace_len[idx];
    }
    len += xqc_put_varint_len(track_status_msg->track_name_len);
    len += track_status_msg->track_name_len;
    len += xqc_put_varint_len(track_status_msg->subscriber_priority);
    len += xqc_put_varint_len(track_status_msg->group_order);
    len += xqc_put_varint_len(track_status_msg->forward);
    len += xqc_put_varint_len(track_status_msg->filter_type);
    if(track_status_msg->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START ||
        track_status_msg->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        len += xqc_put_varint_len(track_status_msg->start_location);
    }
    if(track_status_msg->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        len += xqc_put_varint_len(track_status_msg->end_group);
    }
    len += xqc_put_varint_len(track_status_msg->params_num);
    len += xqc_moq_msg_encode_params_len(track_status_msg->params, track_status_msg->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_track_status(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_track_status_msg_t *track_status_msg = (xqc_moq_track_status_msg_t *)msg_base;
    uint64_t length = xqc_moq_msg_encode_track_status_len(msg_base);
    if(length > buf_cap){
        return -XQC_EILLEGAL_FRAME;
    }

    length -= xqc_put_varint_len(XQC_MOQ_MSG_TRACK_STATUS) + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_TRACK_STATUS);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, track_status_msg->request_id);
    p = xqc_put_varint(p, track_status_msg->track_namespace->track_namespace_num);
    for(size_t idx = 0; idx < track_status_msg->track_namespace->track_namespace_num; idx++) {
        p = xqc_put_varint(p, track_status_msg->track_namespace->track_namespace_len[idx]);
        xqc_memcpy(p, track_status_msg->track_namespace->track_namespace[idx], track_status_msg->track_namespace->track_namespace_len[idx]);
        p += track_status_msg->track_namespace->track_namespace_len[idx];
    }
    p = xqc_put_varint(p, track_status_msg->track_name_len);
    xqc_memcpy(p, track_status_msg->track_name, track_status_msg->track_name_len);
    p += track_status_msg->track_name_len;
    p = xqc_put_varint(p, track_status_msg->subscriber_priority);
    p = xqc_put_varint(p, track_status_msg->group_order);
    p = xqc_put_varint(p, track_status_msg->forward);
    p = xqc_put_varint(p, track_status_msg->filter_type);
    if(track_status_msg->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START ||
        track_status_msg->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        p = xqc_put_varint(p, track_status_msg->start_location);
    }
    if(track_status_msg->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        p = xqc_put_varint(p, track_status_msg->end_group);
    }
    p = xqc_put_varint(p, track_status_msg->params_num);
    ret = xqc_moq_msg_encode_params(track_status_msg->params, track_status_msg->params_num, p, buf_cap - (p - buf));
    if(ret < 0) {
        return ret;
    }
    p += ret;
    return p - buf;
}

xqc_int_t xqc_moq_msg_subscribe_namespace_ok_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK;
}

void
xqc_moq_msg_subscribe_namespace_ok_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = subscribe_namespace_ok_base;
}

void
xqc_moq_msg_unsubscribe_namespace_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = unsubscribe_namespace_base;
}

void *
xqc_moq_msg_create_subscribe_namespace_ok(xqc_moq_session_t *session)
{
    xqc_moq_subscribe_namespace_ok_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg == NULL) {
        return NULL;
    }
    xqc_moq_msg_subscribe_namespace_ok_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_subscribe_namespace_ok(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok = (xqc_moq_subscribe_namespace_ok_msg_t *)msg;
    xqc_free(subscribe_namespace_ok);
}

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace_ok_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(((xqc_moq_subscribe_namespace_ok_msg_t *)msg_base)->request_id);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok = (xqc_moq_subscribe_namespace_ok_msg_t *)msg_base;
    uint64_t length = xqc_moq_msg_encode_subscribe_namespace_ok_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, subscribe_namespace_ok->request_id);
    return p - buf;
}

xqc_int_t
xqc_moq_msg_subscribe_namespace_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
}

void
xqc_moq_msg_subscribe_namespace_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = subscribe_namespace_base;
}

void *
xqc_moq_msg_create_subscribe_namespace(xqc_moq_session_t *session)
{
    printf("xqc_moq_msg_create_subscribe_namespace\n"); // TODO remove it later just for debug 
    xqc_moq_subscribe_namespace_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg == NULL) {
        return NULL;
    }
    msg->params_num = -1;  /* CRITICAL: Mark as uninitialized for decode! */
    xqc_moq_msg_subscribe_namespace_init_handler(&msg->msg_base, session);
    return msg;
}

void
xqc_moq_msg_free_subscribe_namespace(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace = (xqc_moq_subscribe_namespace_msg_t *)msg;
    xqc_moq_msg_free_track_namespace(subscribe_namespace->track_namespace_prefix);
    xqc_free(subscribe_namespace->params);
    xqc_free(subscribe_namespace);
}

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace = (xqc_moq_subscribe_namespace_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe_namespace->request_id);
    len += xqc_moq_msg_encode_track_namespace_len(subscribe_namespace->track_namespace_prefix);
    len += xqc_put_varint_len(subscribe_namespace->params_num);
    len += xqc_moq_msg_encode_params_len(subscribe_namespace->params, subscribe_namespace->params_num);
    printf("encode subscribe namespace len: %d\n", len);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace = (xqc_moq_subscribe_namespace_msg_t *)msg_base;
    uint64_t length = xqc_moq_msg_encode_subscribe_namespace_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, subscribe_namespace->request_id);
    
    p = xqc_put_varint(p, subscribe_namespace->track_namespace_prefix->track_namespace_num);
    for (size_t idx = 0; idx < subscribe_namespace->track_namespace_prefix->track_namespace_num; idx++) {
        p = xqc_put_varint(p, subscribe_namespace->track_namespace_prefix->track_namespace_len[idx]);
        xqc_memcpy(p, subscribe_namespace->track_namespace_prefix->track_namespace[idx], 
                   subscribe_namespace->track_namespace_prefix->track_namespace_len[idx]);
        p += subscribe_namespace->track_namespace_prefix->track_namespace_len[idx];
    }

    p = xqc_put_varint(p, subscribe_namespace->params_num);
    if (subscribe_namespace->params_num > 0) {
        xqc_int_t params_len = xqc_moq_msg_encode_params(subscribe_namespace->params, 
                                                        subscribe_namespace->params_num, 
                                                        p, buf_cap - (p - buf));
        if (params_len < 0) {
            return params_len;
        }
        p += params_len;
    }
    
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_subscribe_namespace(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    printf("xqc_moq_msg_decode_subscribe_namespace\n"); // TODO remove it later just for debug 
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace = (xqc_moq_subscribe_namespace_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;

        case 1: // request_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_namespace->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
            
        case 2: // track_namespace_prefix
            if (subscribe_namespace->track_namespace_prefix == NULL) {
                subscribe_namespace->track_namespace_prefix = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
                subscribe_namespace->track_namespace_prefix->track_namespace_num = -1;
            }
            
            if (subscribe_namespace->track_namespace_prefix->track_namespace_num == -1) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_namespace->track_namespace_prefix->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                
                if (subscribe_namespace->track_namespace_prefix->track_namespace_num > 0) {
                    subscribe_namespace->track_namespace_prefix->track_namespace = 
                        xqc_calloc(subscribe_namespace->track_namespace_prefix->track_namespace_num, sizeof(char*));
                    subscribe_namespace->track_namespace_prefix->track_namespace_len = 
                        xqc_calloc(subscribe_namespace->track_namespace_prefix->track_namespace_num, sizeof(uint64_t));
                }
            }
            
            for (; msg_ctx->cur_array_idx < subscribe_namespace->track_namespace_prefix->track_namespace_num; msg_ctx->cur_array_idx++) {
                if (subscribe_namespace->track_namespace_prefix->track_namespace_len[msg_ctx->cur_array_idx] == 0) {
                    ret = xqc_vint_read(buf + processed, buf + buf_len, 
                                       &subscribe_namespace->track_namespace_prefix->track_namespace_len[msg_ctx->cur_array_idx]);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                }
                
                printf("msg_ctx->cur_array_idx: %d\n", msg_ctx->cur_array_idx); // TODO remove it later just for debug 
                printf("subscribe_namespace->track_namespace_prefix->track_namespace_len[msg_ctx->cur_array_idx]: %llu\n",
                    subscribe_namespace->track_namespace_prefix->track_namespace_len[msg_ctx->cur_array_idx]); // TODO remove it later just for debug 
                if (subscribe_namespace->track_namespace_prefix->track_namespace[msg_ctx->cur_array_idx] == NULL) {
                    if (subscribe_namespace->track_namespace_prefix->track_namespace_len[msg_ctx->cur_array_idx] > XQC_MOQ_MAX_NAME_LEN) {
                        return -XQC_ELIMIT;
                    }
                    subscribe_namespace->track_namespace_prefix->track_namespace[msg_ctx->cur_array_idx] = 
                        xqc_calloc(1, subscribe_namespace->track_namespace_prefix->track_namespace_len[msg_ctx->cur_array_idx] + 1);
                }
                
                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                } else if (subscribe_namespace->track_namespace_prefix->track_namespace_len[msg_ctx->cur_array_idx] - msg_ctx->str_processed <= buf_len - processed) {
                    xqc_memcpy(subscribe_namespace->track_namespace_prefix->track_namespace[msg_ctx->cur_array_idx] + msg_ctx->str_processed, 
                              buf + processed, 
                              subscribe_namespace->track_namespace_prefix->track_namespace_len[msg_ctx->cur_array_idx] - msg_ctx->str_processed);
                    processed += subscribe_namespace->track_namespace_prefix->track_namespace_len[msg_ctx->cur_array_idx] - msg_ctx->str_processed;
                    msg_ctx->str_processed = 0; // track_namespace element finished
                } else {
                    xqc_memcpy(subscribe_namespace->track_namespace_prefix->track_namespace[msg_ctx->cur_array_idx] + msg_ctx->str_processed, 
                              buf + processed, 
                              buf_len - processed);
                    msg_ctx->str_processed += buf_len - processed;
                    processed += buf_len - processed;
                    *wait_more_data = 1;
                    break;
                }
            }
            
            if (*wait_more_data == 1) {
                break;
            }
            
            printf("[DECODE_SUB_NS] case 2 finished, advancing to case 3 (params_num)\n");
            printf("[DECODE_SUB_NS] processed=%d, buf_len=%zu\n", processed, buf_len);
            msg_ctx->cur_field_idx = 3;
            
        case 3: // params_num
            printf("[DECODE_SUB_NS] case 3: params_num, current value=%lld\n", (long long)subscribe_namespace->params_num);
            if (subscribe_namespace->params_num == -1) {
                uint64_t params_num_val;
                printf("[DECODE_SUB_NS] Reading params_num from buf+%d, remaining=%zu bytes\n", 
                       processed, buf_len - processed);
                ret = xqc_vint_read(buf + processed, buf + buf_len, &params_num_val);
                if (ret < 0) {
                    printf("[DECODE_SUB_NS] params_num read failed, wait_more_data\n");
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                subscribe_namespace->params_num = params_num_val;
                printf("[DECODE_SUB_NS] params_num read: %llu, consumed %d bytes, total processed=%d\n",
                       (unsigned long long)params_num_val, ret, processed);
                
                if (subscribe_namespace->params_num > 0) {
                    subscribe_namespace->params = xqc_calloc(subscribe_namespace->params_num, sizeof(xqc_moq_message_parameter_t));
                    if (subscribe_namespace->params == NULL) {
                        return -XQC_EMALLOC;
                    }
                }
            } else {
                printf("[DECODE_SUB_NS] params_num already set to %lld, skipping read\n", (long long)subscribe_namespace->params_num);
            }
            
            printf("[DECODE_SUB_NS] Advancing to case 4 (params decode)\n");
            msg_ctx->cur_field_idx = 4;
            
        case 4: // params
            printf("[DECODE_SUB_NS] case 4: decoding params, params_num=%lld\n", (long long)subscribe_namespace->params_num);
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                subscribe_namespace->params, subscribe_namespace->params_num,
                &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                printf("decode subscribe announces params finish\n"); // TODO remove it later just for debug 
                *finish = 1;
            }
            break;
            
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

void
xqc_moq_msg_free_track_namespace(xqc_moq_msg_track_namespace_t *namespace)
{
    if (namespace == NULL) {
        return;
    }
    
    if (namespace->track_namespace != NULL) {
        for (size_t idx = 0; idx < namespace->track_namespace_num; idx++) {
            xqc_free(namespace->track_namespace[idx]);
        }
        xqc_free(namespace->track_namespace);
    }
    
    xqc_free(namespace->track_namespace_len);
    xqc_free(namespace);
}

xqc_int_t
xqc_moq_msg_subscribe_done_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_DONE;
}

xqc_int_t
xqc_moq_msg_encode_unsubscribe_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    len += xqc_put_varint_len(XQC_MOQ_MSG_UNSUBSCRIBE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(((xqc_moq_unsubscribe_msg_t *)msg_base)->subscribe_id);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_unsubscribe(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_unsubscribe_msg_t *unsubscribe = (xqc_moq_unsubscribe_msg_t *)msg_base;
    uint64_t length = xqc_moq_msg_encode_unsubscribe_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_UNSUBSCRIBE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_UNSUBSCRIBE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, unsubscribe->subscribe_id);
    return p - buf;
}

xqc_int_t
xqc_moq_msg_encode_fetch_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_fetch_msg_t *fetch = (xqc_moq_fetch_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_FETCH);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(fetch->subscribe_id);
    len += xqc_put_varint_len(fetch->subscriber_priority);
    len += xqc_put_varint_len(fetch->group_order);
    len += xqc_put_varint_len(fetch->fetch_type);
    
    if (fetch->fetch_type == XQC_MOQ_FETCH_TYPE_STANDALONE && fetch->fetch_ranges != NULL) {
        len += xqc_moq_msg_encode_track_namespace_len(fetch->fetch_ranges->track_namespace);
        len += xqc_put_varint_len(fetch->fetch_ranges->start_group_id);
        len += xqc_put_varint_len(fetch->fetch_ranges->start_object_id);
        len += xqc_put_varint_len(fetch->fetch_ranges->end_group_id);
        len += xqc_put_varint_len(fetch->fetch_ranges->end_object_id);
    } else if (fetch->fetch_type == XQC_MOQ_FETCH_TYPE_JOINING && fetch->fetch_joining_fetch_range != NULL) {
        len += xqc_put_varint_len(fetch->fetch_joining_fetch_range->joining_subscribe_id);
        len += xqc_put_varint_len(fetch->fetch_joining_fetch_range->preceding_group_offset);
    }
    
    len += xqc_moq_msg_encode_params_len(fetch->params, fetch->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_fetch(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_fetch_msg_t *fetch = (xqc_moq_fetch_msg_t *)msg_base;
    uint64_t length = xqc_moq_msg_encode_fetch_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_FETCH) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_FETCH);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, fetch->subscribe_id);
    p = xqc_put_varint(p, fetch->subscriber_priority);
    p = xqc_put_varint(p, fetch->group_order);
    p = xqc_put_varint(p, fetch->fetch_type);
    
    if (fetch->fetch_type == XQC_MOQ_FETCH_TYPE_STANDALONE && fetch->fetch_ranges != NULL) {
        p = xqc_put_varint(p, fetch->fetch_ranges->track_namespace->track_namespace_num);
        for (size_t idx = 0; idx < fetch->fetch_ranges->track_namespace->track_namespace_num; idx++) {
            p = xqc_put_varint(p, fetch->fetch_ranges->track_namespace->track_namespace_len[idx]);
            xqc_memcpy(p, fetch->fetch_ranges->track_namespace->track_namespace[idx], 
                       fetch->fetch_ranges->track_namespace->track_namespace_len[idx]);
            p += fetch->fetch_ranges->track_namespace->track_namespace_len[idx];
        }
        p = xqc_put_varint(p, fetch->fetch_ranges->start_group_id);
        p = xqc_put_varint(p, fetch->fetch_ranges->start_object_id);
        p = xqc_put_varint(p, fetch->fetch_ranges->end_group_id);
        p = xqc_put_varint(p, fetch->fetch_ranges->end_object_id);
    } else if (fetch->fetch_type == XQC_MOQ_FETCH_TYPE_JOINING && fetch->fetch_joining_fetch_range != NULL) {
        p = xqc_put_varint(p, fetch->fetch_joining_fetch_range->joining_subscribe_id);
        p = xqc_put_varint(p, fetch->fetch_joining_fetch_range->preceding_group_offset);
    }
    
    if (fetch->params_num > 0) {
        xqc_int_t params_len = xqc_moq_msg_encode_params(fetch->params, fetch->params_num, 
                                                        p, buf_cap - (p - buf));
        if (params_len < 0) {
            return params_len;
        }
        p += params_len;
    }
    
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_fetch(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_moq_fetch_msg_t *fetch = (xqc_moq_fetch_msg_t *)msg_base;
    
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
            
        case 1: // subscribe_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &fetch->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
            
        case 2: // subscriber_priority
            ret = xqc_vint_read(buf + processed, buf + buf_len, &fetch->subscriber_priority);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 3;
            
        case 3: // group_order
            ret = xqc_vint_read(buf + processed, buf + buf_len, &fetch->group_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 4;
            
        case 4: // fetch_type
            ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t*)&fetch->fetch_type);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            *finish = 1; // Simplified for basic functionality
            break;
            
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

xqc_int_t
xqc_moq_msg_decode_subgroup_object(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_subgroup_object_msg_t *subgroup_obj = (xqc_moq_subgroup_object_msg_t *)msg_base;
    
    switch (msg_ctx->cur_field_idx) {
        case 0: // object_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subgroup_obj->object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;


        case 1: // payload_len
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subgroup_obj->payload_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (subgroup_obj->payload_len > 0) {
                subgroup_obj->payload = xqc_realloc(subgroup_obj->payload, subgroup_obj->payload_len);
                if (subgroup_obj->payload == NULL) {
                    return -XQC_EILLEGAL_FRAME;
                }
            }
            msg_ctx->payload_processed = 0;
            msg_ctx->cur_field_idx = 3;
            
        case 2: // payload
            if(subgroup_obj->payload_len == 0) {
                *finish = 1;
                break;
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (subgroup_obj->payload_len - msg_ctx->payload_processed <= buf_len - processed) {
                xqc_memcpy(subgroup_obj->payload + msg_ctx->payload_processed, buf + processed,
                           subgroup_obj->payload_len - msg_ctx->payload_processed);
                processed += subgroup_obj->payload_len - msg_ctx->payload_processed;
                msg_ctx->payload_processed = 0;
                *finish = 1;
            } else {
                xqc_memcpy(subgroup_obj->payload + msg_ctx->payload_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->payload_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            break;
            
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

xqc_int_t
xqc_moq_msg_decode_subgroup_object_ext(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    printf("decode subgroup object ext\n");
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_subgroup_object_msg_ext_t *subgroup_obj = (xqc_moq_subgroup_object_msg_ext_t *)msg_base;

    switch (msg_ctx->cur_field_idx) {
        case 0: // object_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subgroup_obj->object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: // extension header length
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subgroup_obj->extension_header_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (subgroup_obj->extension_header_len > 0) {
                subgroup_obj->extension_header = xqc_realloc(subgroup_obj->extension_header,
                    subgroup_obj->extension_header_len);
                if (subgroup_obj->extension_header == NULL) {
                    return -XQC_EILLEGAL_FRAME;
                }
            } else {
                if (subgroup_obj->extension_header) {
                    xqc_free(subgroup_obj->extension_header);
                    subgroup_obj->extension_header = NULL;
                }
            }
            msg_ctx->str_processed = 0;
            msg_ctx->cur_field_idx = 2;
        case 2: // extension header bytes
            if (subgroup_obj->extension_header_len > 0) {
                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                }
                size_t remain_ext = subgroup_obj->extension_header_len - msg_ctx->str_processed;
                size_t avail_ext = buf_len - processed;
                size_t copy = xqc_min(remain_ext, avail_ext);
                xqc_memcpy(subgroup_obj->extension_header + msg_ctx->str_processed, buf + processed, copy);
                msg_ctx->str_processed += copy;
                processed += copy;
                if (msg_ctx->str_processed == subgroup_obj->extension_header_len) {
                    msg_ctx->str_processed = 0;
                    msg_ctx->cur_field_idx = 3;
                } else {
                    *wait_more_data = 1;
                    break;
                }
            } else {
                msg_ctx->cur_field_idx = 3;
            }
        case 3: // payload length
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subgroup_obj->payload_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (subgroup_obj->payload_len > 0) {
                subgroup_obj->payload = xqc_realloc(subgroup_obj->payload, subgroup_obj->payload_len);
                if (subgroup_obj->payload == NULL) {
                    return -XQC_EILLEGAL_FRAME;
                }
            }
            msg_ctx->payload_processed = 0;
            msg_ctx->cur_field_idx = 4;

        case 4: // payload bytes
            if (subgroup_obj->payload_len == 0) {
                *finish = 1;
                break;
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            }
            if (subgroup_obj->payload_len - msg_ctx->payload_processed <= buf_len - processed) {
                xqc_memcpy(subgroup_obj->payload + msg_ctx->payload_processed, buf + processed,
                           subgroup_obj->payload_len - msg_ctx->payload_processed);
                processed += subgroup_obj->payload_len - msg_ctx->payload_processed;
                msg_ctx->payload_processed = 0;
                *finish = 1;
            } else {
                size_t avail = buf_len - processed;
                xqc_memcpy(subgroup_obj->payload + msg_ctx->payload_processed, buf + processed, avail);
                msg_ctx->payload_processed += avail;
                processed += avail;
                *wait_more_data = 1;
                break;
            }
            break;

        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

xqc_int_t
xqc_moq_msg_encode_track_status_ok_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_track_status_ok_msg_t *track_status_ok = (xqc_moq_track_status_ok_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_TRACK_STATUS_OK);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(track_status_ok->request_id);
    len += xqc_put_varint_len(track_status_ok->track_alias);
    len += xqc_put_varint_len(track_status_ok->expires);
    len += XQC_MOQ_GROUP_ORDER_SIZE; // Group Order (8 bits)
    len += XQC_MOQ_CONTENT_EXISTS_SIZE; // Content Exists (8 bits)
    if (track_status_ok->content_exists == 1) {
        len += xqc_put_varint_len(track_status_ok->largest_location);
    }
    len += xqc_put_varint_len(track_status_ok->params_num);
    len += xqc_moq_msg_encode_params_len(track_status_ok->params, track_status_ok->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_track_status_error_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_track_status_error_msg_t *track_status_error = (xqc_moq_track_status_error_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_TRACK_STATUS_ERROR);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(track_status_error->request_id);
    len += xqc_put_varint_len(track_status_error->error_code);
    len += xqc_put_varint_len(track_status_error->error_reason_len);
    len += track_status_error->error_reason_len;
    return len;
}

xqc_int_t
xqc_moq_msg_encode_track_status_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_track_status_error_msg_t *track_status_error = (xqc_moq_track_status_error_msg_t*)msg_base;
    uint64_t length = xqc_moq_msg_encode_track_status_error_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_TRACK_STATUS_ERROR) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_TRACK_STATUS_ERROR);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, track_status_error->request_id);
    p = xqc_put_varint(p, track_status_error->error_code);
    p = xqc_put_varint(p, track_status_error->error_reason_len);
    if (track_status_error->error_reason_len > 0) {
        xqc_memcpy(p, track_status_error->error_reason, track_status_error->error_reason_len);
        p += track_status_error->error_reason_len;
    }
    return p - buf;
}

xqc_int_t
xqc_moq_msg_encode_track_status_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_track_status_ok_msg_t *track_status_ok = (xqc_moq_track_status_ok_msg_t*)msg_base;
    uint64_t length = xqc_moq_msg_encode_track_status_ok_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_TRACK_STATUS_OK) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_TRACK_STATUS_OK);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, track_status_ok->request_id);
    p = xqc_put_varint(p, track_status_ok->track_alias);
    p = xqc_put_varint(p, track_status_ok->expires);
    p = xqc_put_varint(p, track_status_ok->group_order);
    p = xqc_put_varint(p, track_status_ok->content_exists);
    if (track_status_ok->content_exists == 1) {
        p = xqc_put_varint(p, track_status_ok->largest_location);
    } else {
        p = xqc_put_varint(p, 0);
    }
    p = xqc_put_varint(p, track_status_ok->params_num);
    ret = xqc_moq_msg_encode_params(track_status_ok->params, track_status_ok->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_track_status_ok(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_moq_track_status_ok_msg_t *track_status_ok = (xqc_moq_track_status_ok_msg_t *)msg_base;

    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;

        case 1: // request_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status_ok->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;

        case 2: // track_alias
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status_ok->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 3;

        case 3: // expires
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status_ok->expires);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 4;

        case 4: // group_order
            if (processed >= buf_len) {
                *wait_more_data = 1;
                break;
            }
            track_status_ok->group_order = buf[processed++];
            msg_ctx->cur_field_idx = 5;

        case 5: // content_exists
            if (processed >= buf_len) {
                *wait_more_data = 1;
                break;
            }
            track_status_ok->content_exists = buf[processed++];
            msg_ctx->cur_field_idx = 6;

        case 6: // largest_location (if content_exists)
            if (track_status_ok->content_exists == 1) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status_ok->largest_location);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
            }
            msg_ctx->cur_field_idx = 7;

        case 7: // params_num
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status_ok->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (track_status_ok->params_num > 0) {
                track_status_ok->params = xqc_moq_msg_alloc_params(track_status_ok->params_num);
                if (track_status_ok->params == NULL) {
                    return -XQC_EMALLOC;
                }
            }
            msg_ctx->cur_field_idx = 8;

        case 8: // params
            if (track_status_ok->params_num > 0) {
                xqc_moq_decode_params_ctx_t params_ctx;
                xqc_moq_decode_params_ctx_reset(&params_ctx);
                xqc_int_t params_finish = 0;
                ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, &params_ctx,
                                                track_status_ok->params, track_status_ok->params_num,
                                                &params_finish, wait_more_data);
                if (ret < 0) {
                    return ret;
                }
                if (*wait_more_data == 1) {
                    break;
                }
                processed += ret;
            }
            *finish = 1;
            break;

        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

xqc_int_t
xqc_moq_msg_decode_track_status_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_moq_track_status_error_msg_t *track_status_error = (xqc_moq_track_status_error_msg_t *)msg_base;

    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;

        case 1: // request_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status_error->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;

        case 2: // error_code
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status_error->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 3;

        case 3: // error_reason_len
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status_error->error_reason_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (track_status_error->error_reason_len > 0) {
                track_status_error->error_reason = xqc_malloc(track_status_error->error_reason_len + 1);
                if (track_status_error->error_reason == NULL) {
                    return -XQC_EMALLOC;
                }
                memset(track_status_error->error_reason, 0, track_status_error->error_reason_len + 1);
            }
            msg_ctx->cur_field_idx = 4;

        case 4: // error_reason
            if (track_status_error->error_reason_len > 0) {
                if (processed + track_status_error->error_reason_len <= buf_len) {
                    xqc_memcpy(track_status_error->error_reason, buf + processed, track_status_error->error_reason_len);
                    processed += track_status_error->error_reason_len;
                    *finish = 1;
                } else {
                    xqc_memcpy(track_status_error->error_reason + msg_ctx->str_processed, buf + processed, buf_len - processed);
                    msg_ctx->str_processed += buf_len - processed;
                    processed = buf_len;
                    *wait_more_data = 1;
                }
            } else {
                *finish = 1;
            }
            break;

        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

xqc_int_t
xqc_moq_msg_decode_track_status(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_moq_track_status_msg_t *track_status = (xqc_moq_track_status_msg_t *)msg_base;
    uint64_t subscriber_priority = 0;
    uint64_t group_order = 0;
    uint64_t forward = 0;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;

    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;

        case 1: // request_id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
            
        case 2: // track_namespace
            if (msg_ctx->cur_array_idx == 0) {
                // Read namespace count
                if(track_status->track_namespace == NULL) {
                    track_status->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
                }
                ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status->track_namespace->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;

                track_status->track_namespace->track_namespace_len = xqc_calloc(track_status->track_namespace->track_namespace_num, sizeof(uint64_t));
                track_status->track_namespace->track_namespace = xqc_calloc(track_status->track_namespace->track_namespace_num, sizeof(char*));
                
                msg_ctx->cur_array_idx = 1;
            }
            
            // Read namespace entries
            while (msg_ctx->cur_array_idx <= track_status->track_namespace->track_namespace_num * 2) {
                uint64_t idx = (msg_ctx->cur_array_idx - 1) / 2;
                
                if (msg_ctx->cur_array_idx % 2 == 1) {
                    // Read namespace length
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status->track_namespace->track_namespace_len[idx]);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                    track_status->track_namespace->track_namespace[idx] = xqc_malloc(track_status->track_namespace->track_namespace_len[idx] + 1);
                    
                } else {
                    // Read namespace value
                    if (processed + track_status->track_namespace->track_namespace_len[idx] > buf_len) {
                        *wait_more_data = 1;
                        break;
                    }
                    
                    xqc_memcpy(track_status->track_namespace->track_namespace[idx], 
                        buf + processed, 
                        track_status->track_namespace->track_namespace_len[idx]);
                    track_status->track_namespace->track_namespace[idx][track_status->track_namespace->track_namespace_len[idx]] = '\0';
                    processed += track_status->track_namespace->track_namespace_len[idx];
                }
                
                msg_ctx->cur_array_idx++;
            }
            
            if (*wait_more_data) {
                break;
            }
            
            msg_ctx->cur_field_idx = 3;
            msg_ctx->cur_array_idx = 0;
            
        case 3: // track_name_len and track_name
            if(msg_ctx->cur_array_idx == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status->track_name_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                msg_ctx->cur_array_idx = 1;
            }

            if(msg_ctx->cur_array_idx == 1) {
                if (processed + track_status->track_name_len > buf_len) {
                    *wait_more_data = 1;
                    break;
                }
                
                if (track_status->track_name_len > 0) {
                    track_status->track_name = xqc_calloc(track_status->track_name_len + 1, sizeof(char));
                    xqc_memcpy(track_status->track_name, buf + processed, track_status->track_name_len);
                    track_status->track_name[track_status->track_name_len] = '\0';
                }
            }
            processed += track_status->track_name_len;
            msg_ctx->cur_field_idx = 4;
            msg_ctx->cur_array_idx = 0;
            
        case 4: // subscriber_priority
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscriber_priority);
            track_status->subscriber_priority = (uint8_t)subscriber_priority;
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 5;
            
        case 5: // group_order
            ret = xqc_vint_read(buf + processed, buf + buf_len, &group_order);
            track_status->group_order = (uint8_t)group_order;
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 6;
            
        case 6: // forward
            ret = xqc_vint_read(buf + processed, buf + buf_len, &forward);
            track_status->forward = (uint8_t)forward;
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 7;
            
        case 7: // filter_type
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status->filter_type);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (track_status->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START ||
                track_status->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 8;

            } else {
                msg_ctx->cur_field_idx = 10;
                goto idx10;
            }
        case 8: // start_location
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status->start_location);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if(track_status->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 9;
            } else {
                msg_ctx->cur_field_idx = 10;
                goto idx10;
            }
        case 9: // end_group
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status->end_group);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 10;
        case 10: // params_num
            idx10:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_status->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 11;
        case 11: // params
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            track_status->params, track_status->params_num,
                                            finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            *finish = 1;
            break;
        
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

xqc_int_t
xqc_moq_msg_unsubscribe_namespace_type()
{
    return XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE;
}

xqc_int_t
xqc_moq_msg_encode_unsubscribe_namespace_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t length = 0;
    xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace = (xqc_moq_unsubscribe_namespace_msg_t *)msg_base;
    length += xqc_put_varint_len(XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE);
    length += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    length += xqc_put_varint_len(unsubscribe_namespace->track_namespace_prefix->track_namespace_num);
    for (uint64_t i = 0; i < unsubscribe_namespace->track_namespace_prefix->track_namespace_num; i++) {
        length += xqc_put_varint_len(unsubscribe_namespace->track_namespace_prefix->track_namespace_len[i]);
        length += unsubscribe_namespace->track_namespace_prefix->track_namespace_len[i];
    }
    return length;
}

xqc_int_t 
xqc_moq_msg_encode_unsubscribe_namespace(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace = (xqc_moq_unsubscribe_namespace_msg_t *)msg_base;
    uint64_t length = xqc_moq_msg_encode_unsubscribe_namespace_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, unsubscribe_namespace->track_namespace_prefix->track_namespace_num);
    for (uint64_t i = 0; i < unsubscribe_namespace->track_namespace_prefix->track_namespace_num; i++) {
        p = xqc_put_varint(p, unsubscribe_namespace->track_namespace_prefix->track_namespace_len[i]);
        xqc_memcpy(p, unsubscribe_namespace->track_namespace_prefix->track_namespace[i],
             unsubscribe_namespace->track_namespace_prefix->track_namespace_len[i]);
        p += unsubscribe_namespace->track_namespace_prefix->track_namespace_len[i];
    }
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_unsubscribe_namespace(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace = (xqc_moq_unsubscribe_namespace_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;

        case 1: // track_namespace_prefix_num
            if (msg_ctx->cur_array_idx == 0) {
                // Read namespace count
                if(unsubscribe_namespace->track_namespace_prefix == NULL) {
                    unsubscribe_namespace->track_namespace_prefix = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
                }
                ret = xqc_vint_read(buf + processed, buf + buf_len, &unsubscribe_namespace->track_namespace_prefix->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;

                unsubscribe_namespace->track_namespace_prefix->track_namespace_len = xqc_calloc(unsubscribe_namespace->track_namespace_prefix->track_namespace_num, sizeof(uint64_t));
                unsubscribe_namespace->track_namespace_prefix->track_namespace = xqc_calloc(unsubscribe_namespace->track_namespace_prefix->track_namespace_num, sizeof(char*));
                
                msg_ctx->cur_array_idx = 1;
            }
            
            // Read namespace entries
            while (msg_ctx->cur_array_idx <= unsubscribe_namespace->track_namespace_prefix->track_namespace_num * 2) {
                uint64_t idx = (msg_ctx->cur_array_idx - 1) / 2;
                
                if (msg_ctx->cur_array_idx % 2 == 1) {
                    // Read namespace length
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &unsubscribe_namespace->track_namespace_prefix->track_namespace_len[idx]);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                    unsubscribe_namespace->track_namespace_prefix->track_namespace[idx] = xqc_malloc(unsubscribe_namespace->track_namespace_prefix->track_namespace_len[idx] + 1);
                    
                } else {
                    // Read namespace value
                    if (processed + unsubscribe_namespace->track_namespace_prefix->track_namespace_len[idx] > buf_len) {
                        *wait_more_data = 1;
                        break;
                    }
                    
                    xqc_memcpy(unsubscribe_namespace->track_namespace_prefix->track_namespace[idx], 
                        buf + processed, 
                        unsubscribe_namespace->track_namespace_prefix->track_namespace_len[idx]);
                    unsubscribe_namespace->track_namespace_prefix->track_namespace[idx][unsubscribe_namespace->track_namespace_prefix->track_namespace_len[idx]] = '\0';
                    processed += unsubscribe_namespace->track_namespace_prefix->track_namespace_len[idx];
                }
                
                msg_ctx->cur_array_idx++;
            }
            
            if (*wait_more_data) {
                break;
            }
            
            msg_ctx->cur_field_idx = 3;
            msg_ctx->cur_array_idx = 0;
            *finish = 1;
            break;
            
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}



void *xqc_moq_msg_create_publish_namespace(xqc_moq_session_t *session)
{
    xqc_moq_publish_namespace_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_namespace_init_handler(&msg->msg_base, session);
    return msg;
}

void xqc_moq_msg_free_publish_namespace(void *m)
{
    xqc_moq_publish_namespace_msg_t *msg = m;
    if (msg == NULL) return;
    if (msg->track_namespace) {
        xqc_moq_msg_free_track_namespace(msg->track_namespace);
    }
    xqc_free(msg);
}

void *xqc_moq_msg_create_publish_namespace_done(xqc_moq_session_t *session)
{
    xqc_moq_publish_namespace_done_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_namespace_done_init_handler(&msg->msg_base, session);
    return msg;
}

void xqc_moq_msg_free_publish_namespace_done(void *m)
{
    xqc_moq_publish_namespace_done_msg_t *msg = m;
    if (msg == NULL) return;
    if (msg->track_namespace) {
        xqc_moq_msg_free_track_namespace(msg->track_namespace);
    }
    xqc_free(msg);
}

xqc_int_t xqc_moq_msg_encode_publish_namespace_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_namespace_msg_t *msg = (xqc_moq_publish_namespace_msg_t*)msg_base;
    xqc_int_t len = XQC_MOQ_MSG_LENGTH_FIXED_SIZE; /* length field */
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE);
    len += xqc_vint_len(msg->request_id);
    len += xqc_moq_msg_encode_track_namespace_len(msg->track_namespace);
    len += xqc_put_varint_len(msg->params_num);
    len += xqc_moq_msg_encode_params_len(msg->params, msg->params_num);
    return len;
}

xqc_int_t xqc_moq_msg_encode_publish_namespace(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_publish_namespace_msg_t *msg = (xqc_moq_publish_namespace_msg_t*)msg_base;
    uint8_t *p = buf;
    uint64_t total = xqc_moq_msg_encode_publish_namespace_len(msg_base);
    uint64_t payload_len = total - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_NAMESPACE);
    p = xqc_moq_put_varint_length(p, payload_len);
    p = xqc_put_varint(p, msg->request_id);
    p += xqc_moq_msg_encode_track_namespace(msg->track_namespace, p, buf_cap - (p - buf));
    p = xqc_put_varint(p, msg->params_num);
    if (msg->params_num) {
        xqc_int_t ret = xqc_moq_msg_encode_params(msg->params, msg->params_num, p, buf_cap - (p - buf));
        if (ret < 0) {
            return ret;
        }
        p += ret;
    }
    return (xqc_int_t)(p - buf);
}

xqc_int_t xqc_moq_msg_decode_publish_namespace(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0; *wait_more_data = 0;
    xqc_moq_publish_namespace_msg_t *msg = (xqc_moq_publish_namespace_msg_t*)msg_base;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    xqc_int_t param_finish = 0;
    uint64_t params_num = 0;

    switch (msg_ctx->cur_field_idx) {
        case 0:
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) { *wait_more_data = 1; break; }
            processed += ret; msg_ctx->cur_field_idx = 1;
        case 1: /* request_id */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &msg->request_id);
            if (ret < 0) { *wait_more_data = 1; break; }
            processed += ret; msg_ctx->cur_field_idx = 2;
        case 2: /* track_namespace */
            if (msg->track_namespace == NULL) {
                msg->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
            }
            xqc_int_t ns_finish = 0; xqc_int_t ns_wait = 0;
            ret = xqc_moq_msg_decode_track_namespace(buf + processed, buf_len - processed,
                 &msg_ctx->decode_params_ctx, msg->track_namespace, &ns_finish, &ns_wait);
            if (ret < 0) {
                *wait_more_data = 1;
                break; 
            }
            processed += ret;
            if (ns_wait == 1) {
                *wait_more_data = 1;
                break;
            }
            if (ns_finish == 0) {
                break;
            }
            msg_ctx->cur_field_idx = 3;
        case 3: /* params_num */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &params_num);
            if (ret < 0) { *wait_more_data = 1; break; }
            processed += ret;
            msg->params_num = (xqc_int_t)params_num;
            if (msg->params_num > XQC_MOQ_MAX_PARAMS) { return -XQC_ELIMIT; }
            if (msg->params_num > 0) {
                msg->params = xqc_moq_msg_alloc_params(msg->params_num);
            }
            msg_ctx->cur_field_idx = 4;
        case 4: /* params */
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, &msg_ctx->decode_params_ctx,
                                            msg->params, msg->params_num, &param_finish, wait_more_data);
            if (ret < 0) { 
                return ret; 
            }
            processed += ret;
            if (*wait_more_data == 1) break;
            if (param_finish == 1) { 
                *finish = 1;
                break;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}

xqc_int_t xqc_moq_msg_encode_publish_namespace_done_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_namespace_done_msg_t *msg = (xqc_moq_publish_namespace_done_msg_t*)msg_base;
    xqc_int_t len = XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE);
    len += xqc_moq_msg_encode_track_namespace_len(msg->track_namespace);
    return len;
}

xqc_int_t xqc_moq_msg_encode_publish_namespace_done(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_publish_namespace_done_msg_t *msg = (xqc_moq_publish_namespace_done_msg_t*)msg_base;
    uint8_t *p = buf;
    uint64_t total = xqc_moq_msg_encode_publish_namespace_done_len(msg_base);
    uint64_t payload_len = total - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE);
    p = xqc_moq_put_varint_length(p, payload_len);
    p += xqc_moq_msg_encode_track_namespace(msg->track_namespace, p, buf_cap - (p - buf));
    return (xqc_int_t)(p - buf);
}

xqc_int_t
xqc_moq_msg_decode_publish_namespace_done(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_moq_publish_namespace_done_msg_t *msg = (xqc_moq_publish_namespace_done_msg_t*)msg_base;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t len_expected = 0;
    
    switch (msg_ctx->cur_field_idx) {
        case 0: /* length */
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &len_expected);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
            
        case 1: /* track_namespace */
            if (msg->track_namespace == NULL) {
                msg->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
            }
            ret = xqc_moq_msg_decode_track_namespace(buf + processed, buf_len - processed,
                &msg_ctx->decode_params_ctx, msg->track_namespace, finish, wait_more_data);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (*finish == 0 || *wait_more_data == 1) {
                break;
            }
            *finish = 1;
            break;
            
        default:
            return -XQC_EILLEGAL_FRAME;
    }
    
    return processed;
}

void xqc_moq_msg_publish_namespace_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{ 
    *msg_base = publish_namespace_base; 
}

void xqc_moq_msg_publish_namespace_done_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session)
{
    *msg_base = publish_namespace_done_base; 
}