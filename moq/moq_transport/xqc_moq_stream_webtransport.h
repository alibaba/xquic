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

#endif /* _XQC_MOQ_STREAM_WEBTRANSPORT_H_INCLUDED_ */
