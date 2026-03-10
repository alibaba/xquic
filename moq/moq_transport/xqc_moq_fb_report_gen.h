#ifndef _XQC_MOQ_FB_REPORT_GEN_H_INCLUDED_
#define _XQC_MOQ_FB_REPORT_GEN_H_INCLUDED_

#include "moq/moq_transport/xqc_moq_session.h"

typedef struct xqc_moq_fb_report_gen_s {
    xqc_moq_session_t *session;
    xqc_gp_timer_id_t timer_id;
    xqc_usec_t last_report_ts;
    uint64_t report_sequence;
    xqc_moq_track_t *feedback_track_pub;
} xqc_moq_fb_report_gen_t;

xqc_moq_fb_report_gen_t *xqc_moq_fb_report_gen_create(xqc_moq_session_t *session, xqc_moq_track_t *feedback_track_pub);

void xqc_moq_fb_report_gen_destroy(xqc_moq_fb_report_gen_t *gen);

void xqc_moq_fb_report_gen_on_media_object_received(xqc_moq_session_t *session, xqc_moq_track_t *track,
    const xqc_moq_object_t *object, xqc_usec_t now);

#endif /* _XQC_MOQ_FB_REPORT_GEN_H_INCLUDED_ */
