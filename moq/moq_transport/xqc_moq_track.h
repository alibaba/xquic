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
    void (*on_subscribe)(xqc_moq_session_t *session, uint64_t subscribe_id,
                         xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg);
    void (*on_subscribe_update)(xqc_moq_session_t *session, uint64_t subscribe_id,
                                xqc_moq_track_t *track, xqc_moq_subscribe_update_msg_t *msg); /* Optional */
    void (*on_subscribe_ok)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                            xqc_moq_subscribe_ok_msg_t *subscribe_ok);
    void (*on_subscribe_error)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                               xqc_moq_subscribe_error_msg_t *subscribe_error);
    void (*on_object)(xqc_moq_session_t *session, xqc_moq_track_t *track,
                      xqc_moq_object_t *object);
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
    uint64_t                            cur_subgroup_id;
    uint64_t                            cur_subgroup_group_id;
    uint8_t                             raw_object; // no loc container decode
    xqc_moq_track_ops_t                 track_ops;
    xqc_moq_track_role_t                track_role;
} xqc_moq_track_t;

void xqc_moq_track_destroy(xqc_moq_track_t *track);

void xqc_moq_track_free_fields(xqc_moq_track_t *track);

void xqc_moq_track_set_alias(xqc_moq_track_t *track, uint64_t track_alias);

void xqc_moq_track_set_subscribe_id(xqc_moq_track_t *track, uint64_t subscribe_id);

uint64_t xqc_moq_track_next_subgroup_id(xqc_moq_track_t *track, uint64_t group_id);

void xqc_moq_track_copy_params(xqc_moq_selection_params_t *dst, xqc_moq_selection_params_t *src);

void xqc_moq_track_free_params(xqc_moq_selection_params_t *params);

void xqc_moq_track_set_params(xqc_moq_track_t *track, xqc_moq_selection_params_t *params);

#endif /* _XQC_MOQ_TRACK_H_INCLUDED_ */
