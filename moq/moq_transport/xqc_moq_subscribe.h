#ifndef _XQC_MOQ_SUBSCRIBE_H_INCLUDED_
#define _XQC_MOQ_SUBSCRIBE_H_INCLUDED_

#include "src/common/xqc_list.h"
#include "moq/xqc_moq.h"

typedef struct xqc_moq_subscribe_s {
    xqc_list_head_t                 list_member;
    xqc_moq_subscribe_msg_t         *subscribe_msg;
} xqc_moq_subscribe_t;

xqc_moq_subscribe_t *
xqc_moq_subscribe_create(xqc_moq_session_t *session, uint64_t subscribe_id,
    uint64_t track_alias, const char *track_namespace, const char *track_name, xqc_moq_filter_type_t filter_type,
    uint64_t start_group_id, uint64_t start_object_id, uint64_t end_group_id, uint64_t end_object_id,
    char *authinfo, xqc_int_t is_local);

xqc_moq_subscribe_t *
xqc_moq_subscribe_create_with_ns_tuple(xqc_moq_session_t *session, uint64_t subscribe_id,
    uint64_t track_alias, const xqc_moq_track_ns_field_t *ns_tuple, uint64_t ns_num,
    const char *track_name, xqc_moq_filter_type_t filter_type,
    uint64_t start_group_id, uint64_t start_object_id, uint64_t end_group_id, uint64_t end_object_id,
    char *authinfo, xqc_int_t is_local);

void xqc_moq_subscribe_destroy(xqc_moq_subscribe_t *subscribe);

void xqc_moq_subscribe_update_msg(xqc_moq_subscribe_t *subscribe, xqc_moq_subscribe_update_msg_t *update);

xqc_bool_t xqc_moq_subscribe_update_is_valid(xqc_moq_subscribe_msg_t *cur,
    uint64_t start_group_id, uint64_t start_object_id, uint64_t end_group_id);

xqc_int_t xqc_moq_subscribe_with_ns_tuple(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *ns_tuple, uint64_t ns_num,
    const char *track_name, xqc_moq_filter_type_t filter_type,
    uint64_t start_group_id, uint64_t start_object_id,
    uint64_t end_group_id, uint64_t end_object_id, char *authinfo);

void xqc_moq_session_forward_matching_namespaces(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num);

xqc_int_t xqc_moq_session_forward_namespace_update(
    xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num, xqc_int_t done);

xqc_int_t xqc_moq_prepare_d18_discovered_publish(
    xqc_moq_publish_msg_t *publish, xqc_moq_track_t *track,
    uint8_t forward, xqc_moq_message_parameter_t *forward_param);

void xqc_moq_session_forward_matching_publishes(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple,
    uint64_t namespace_prefix_num, uint8_t forward);

#endif /* _XQC_MOQ_SUBSCRIBE_H_INCLUDED_ */
