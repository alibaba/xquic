#ifndef _XQC_MOQ_DATAGRAM_H_INCLUDED_
#define _XQC_MOQ_DATAGRAM_H_INCLUDED_

#include "xquic/xquic.h"
#include "moq/xqc_moq.h"

extern const xqc_datagram_callbacks_t xqc_moq_quic_dgram_callbacks;

xqc_int_t xqc_moq_datagram_decode(uint8_t *buf, size_t buf_len, xqc_moq_object_datagram_t *object_datagram);

xqc_int_t xqc_moq_datagram_status_decode(uint8_t *buf, size_t buf_len, xqc_moq_object_datagram_status_t *object_datagram_status);

#endif /* _XQC_MOQ_DATAGRAM_H_INCLUDED_ */