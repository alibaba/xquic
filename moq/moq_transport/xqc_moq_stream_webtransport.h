#ifndef _XQC_MOQ_STREAM_WEBTRANSPORT_H_INCLUDED_
#define _XQC_MOQ_STREAM_WEBTRANSPORT_H_INCLUDED_

#include "xquic/xquic.h"
#include "xquic/xqc_webtransport.h"
#include "moq/moq_transport/xqc_moq_stream.h"

extern const xqc_moq_trans_stream_ops_t xqc_moq_wt_stream_ops;

/*
 * WT stream callbacks to register via xqc_wt_ctx_init.
 * Declared here so xqc_moq_session.c can reference them.
 */
extern const xqc_webtransport_stream_callbacks_t xqc_moq_wt_stream_callbacks;

/*
 * Sweep leftover WT stream wrappers on session/connection teardown.
 * Per-stream close_notify is not reliable for this: uni streams never
 * dispatch to it, and bidi streams' dispatch usually misses too since
 * the session is already unregistered by the time it runs.  Call from
 * the session_close_notify app callback (WT objects still valid then);
 * xqc_moq_session_destroy also calls it as a safety net.
 */
void xqc_moq_wt_cleanup_stream_list(xqc_moq_session_t *session);

#endif /* _XQC_MOQ_STREAM_WEBTRANSPORT_H_INCLUDED_ */
