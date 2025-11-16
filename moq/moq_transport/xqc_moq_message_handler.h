#ifndef _XQC_MOQ_MESSAGE_HANDLER_H_INCLUDED_
#define _XQC_MOQ_MESSAGE_HANDLER_H_INCLUDED_

#include "moq/xqc_moq.h"

void xqc_moq_on_client_setup(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_server_setup(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_subscribe(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_subscribe_update(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_publish(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_publish_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_publish_error(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_publish_done(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_object(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_object_t *object);

void xqc_moq_on_object_stream(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_track_stream_obj(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_track_header(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_on_unsubscribe(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

#endif /* _XQC_MOQ_MESSAGE_HANDLER_H_INCLUDED_ */
