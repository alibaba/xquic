#ifndef _XQC_MOQ_TRACK_H_INCLUDED_
#define _XQC_MOQ_TRACK_H_INCLUDED_

#include "src/common/xqc_list.h"
#include "moq/xqc_moq.h"
#include "moq/moq_media/xqc_moq_container.h"

#define XQC_MOQ_CATALOG_NAMESPACE     "catalog"
#define XQC_MOQ_CATALOG_NAME          "catalog"
#define XQC_MOQ_DATACHANNEL_NAMESPACE "datachannel"
#define XQC_MOQ_DATACHANNEL_NAME      "datachannel"


typedef struct xqc_moq_track_ops_s {
    void (*on_create)(xqc_moq_track_t *track);
    void (*on_destroy)(xqc_moq_track_t *track);
    // TODO test
    // void (*on_subscribe)(xqc_moq_session_t *session, uint64_t subscribe_id,
    //                      xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg);
    void (*on_subscribe_v05)(xqc_moq_session_t *session, uint64_t subscribe_id,
                             xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v05 *msg);
    void (*on_subscribe_v13)(xqc_moq_session_t *session, uint64_t subscribe_id,
                             xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v13 *msg);
    void (*on_subscribe_update_v05)(xqc_moq_session_t *session, uint64_t subscribe_id,
                                    xqc_moq_track_t *track, xqc_moq_subscribe_update_msg_t_v05 *msg); /* Optional */
    void (*on_subscribe_update_v13)(xqc_moq_session_t *session, uint64_t subscribe_id,
                                    xqc_moq_track_t *track, xqc_moq_subscribe_update_msg_t_v13 *msg); /* Optional */
    void (*on_subscribe_ok)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                            xqc_moq_subscribe_ok_msg_t *subscribe_ok);
    void (*on_subscribe_error)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                               xqc_moq_subscribe_error_msg_t *subscribe_error);
    void (*on_object)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                      xqc_moq_object_t *object);
    void (*on_subscribe_done)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                xqc_moq_subscribe_done_msg_t *subscribe_done);
    void (*on_announce)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                        xqc_moq_announce_msg_t *announce);
    void (*on_announce_ok)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                           xqc_moq_announce_ok_msg_t *announce_ok);
    void (*on_announce_error)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                              xqc_moq_announce_error_msg_t *announce_error);
    void (*on_goaway)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                      xqc_moq_goaway_msg_t *goaway);
    void (*on_max_request_id)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                                xqc_moq_max_request_id_msg_t *max_request_id);
    void (*on_publish)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                       xqc_moq_publish_msg_t *publish);
} xqc_moq_track_ops_t;

typedef struct xqc_moq_track_s {
    xqc_moq_session_t                   *session;
    xqc_moq_track_info_t                track_info;
    uint64_t                            track_alias;
    uint64_t                            subscribe_id;
    xqc_moq_container_t                 container_format;
    char                                *packaging;
    xqc_int_t                           render_group;
    xqc_list_head_t                     list_member;
    uint64_t                            cur_group_id;
    uint64_t                            cur_object_id;
    xqc_moq_track_ops_t                 track_ops;
    xqc_moq_track_role_t                track_role;
} xqc_moq_track_t;

void xqc_moq_track_destroy(xqc_moq_track_t *track);

void xqc_moq_track_free_fields(xqc_moq_track_t *track);

void xqc_moq_track_set_alias(xqc_moq_track_t *track, uint64_t track_alias);

void xqc_moq_track_set_subscribe_id(xqc_moq_track_t *track, uint64_t subscribe_id);

void xqc_moq_track_copy_params(xqc_moq_selection_params_t *dst, xqc_moq_selection_params_t *src);

void xqc_moq_track_free_params(xqc_moq_selection_params_t *params);

void xqc_moq_track_set_params(xqc_moq_track_t *track, xqc_moq_selection_params_t *params);

#endif /* _XQC_MOQ_TRACK_H_INCLUDED_ */
