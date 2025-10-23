#ifndef _XQC_MOQ_FEC_H_INCLUDED_
#define _XQC_MOQ_FEC_H_INCLUDED_

#include "moq/xqc_moq.h"
#include "src/transport/xqc_stream.h"
#include "moq/moq_transport/xqc_moq_stream.h"

void xqc_init_quic_fec(xqc_moq_stream_t *moq_stream);

#endif /* _XQC_MOQ_FEC_H_INCLUDED_ */
