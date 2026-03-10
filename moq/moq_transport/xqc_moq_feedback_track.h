#ifndef _XQC_MOQ_FEEDBACK_TRACK_H_INCLUDED_
#define _XQC_MOQ_FEEDBACK_TRACK_H_INCLUDED_

#include "moq/moq_transport/xqc_moq_track.h"

extern const xqc_moq_track_ops_t xqc_moq_feedback_track_ops;

void xqc_moq_feedback_start_net_stats_timer(xqc_moq_session_t *session);
void xqc_moq_feedback_stop_net_stats_timer(xqc_moq_session_t *session);

#endif /* _XQC_MOQ_FEEDBACK_TRACK_H_INCLUDED_ */

