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

void xqc_moq_subscribe_destroy(xqc_moq_subscribe_t *subscribe);

void xqc_moq_subscribe_update_msg(xqc_moq_subscribe_t *subscribe, xqc_moq_subscribe_update_msg_t *update);

#endif /* _XQC_MOQ_SUBSCRIBE_H_INCLUDED_ */
