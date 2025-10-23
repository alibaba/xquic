#ifndef _XQC_MOQ_DATACHANNEL_H_INCLUDED_
#define _XQC_MOQ_DATACHANNEL_H_INCLUDED_

#include "moq/xqc_moq.h"
#include "moq/moq_transport/xqc_moq_track.h"

typedef struct {
    xqc_moq_track_t             track;
} xqc_moq_dc_track_t;

typedef struct xqc_moq_datachannel_s {
    xqc_moq_stream_t            *ordered_stream;
    uint64_t                    local_subscribe_id;
    uint64_t                    peer_subscribe_id;
    xqc_moq_track_t             *track_for_pub;
    xqc_moq_track_t             *track_for_sub;
    uint8_t                     can_send;
    uint8_t                     can_recv;
    uint8_t                     ready;
    uint8_t                     msg_header_write;
} xqc_moq_datachannel_t;

extern const struct xqc_moq_track_ops_s xqc_moq_datachannel_track_ops;

void xqc_moq_datachannel_set_can_send(xqc_moq_session_t *session, xqc_moq_datachannel_t *dc);

void xqc_moq_datachannel_set_can_recv(xqc_moq_session_t *session, xqc_moq_datachannel_t *dc);

void xqc_moq_datachannel_update_state(xqc_moq_session_t *session, xqc_moq_datachannel_t *dc);

xqc_int_t xqc_moq_subscribe_datachannel(xqc_moq_session_t *session);

#endif /* _XQC_MOQ_DATACHANNEL_H_INCLUDED_ */
