#ifndef _XQC_MOQ_NAMESPACE_H_INCLUDED_
#define _XQC_MOQ_NAMESPACE_H_INCLUDED_

#include "src/common/xqc_list.h"
#include "moq/xqc_moq.h"
#include "moq/moq_transport/xqc_moq_session.h"

typedef struct xqc_moq_namespace_watch_s {
    uint64_t                    request_id;
    xqc_moq_msg_track_namespace_t *prefix;   /* deep-copied */
    xqc_list_head_t             list_member;
} xqc_moq_namespace_watch_t;

/* lifecycle */
void xqc_moq_namespace_watch_add(xqc_moq_session_t *session, uint64_t request_id,
    xqc_moq_msg_track_namespace_t *prefix);

void xqc_moq_namespace_watch_remove_by_prefix(xqc_moq_session_t *session,
    xqc_moq_msg_track_namespace_t *prefix);

void xqc_moq_namespace_free_all(xqc_moq_session_t *session);

/* utils */
xqc_int_t xqc_moq_namespace_prefix_match(xqc_moq_msg_track_namespace_t *prefix,
    const char *track_namespace);

/* notifications */
void xqc_moq_namespace_notify_on_track_added(xqc_moq_session_t *session,
    xqc_moq_track_t *track);

void xqc_moq_namespace_notify_on_track_removed(xqc_moq_session_t *session,
    xqc_moq_track_t *track);

/* backfill current matching set for a single track to all watches (optional) */
/* void xqc_moq_namespace_backfill_for_track(xqc_moq_session_t *session,
    xqc_moq_track_t *track); */

#endif /* _XQC_MOQ_NAMESPACE_H_INCLUDED_ */


