#ifndef _XQC_MOQ_MESSAGE_WRITER_H_INCLUDED_
#define _XQC_MOQ_MESSAGE_WRITER_H_INCLUDED_

#include "moq/xqc_moq.h"
#include "moq/moq_transport/xqc_moq_message.h"

xqc_int_t xqc_moq_msg_write(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_write_msg_generic(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_msg_base_t *msg_base, xqc_moq_msg_init_handler_pt init_handler);

xqc_int_t xqc_moq_write_client_setup(xqc_moq_session_t *session, xqc_moq_client_setup_msg_t *client_setup);

xqc_int_t xqc_moq_write_server_setup(xqc_moq_session_t *session, xqc_moq_server_setup_msg_t *server_setup);

xqc_int_t xqc_moq_write_subscribe(xqc_moq_session_t *session, xqc_moq_subscribe_msg_t *subscribe);

xqc_int_t xqc_moq_write_subscribe_update(xqc_moq_session_t *session, xqc_moq_subscribe_update_msg_t *update);

xqc_int_t xqc_moq_write_object_stream_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_object_stream_msg_t *object);

xqc_int_t xqc_moq_write_stream_header_track_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_stream_header_track_msg_t *track_header);

xqc_int_t xqc_moq_write_track_stream_obj_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_track_stream_obj_msg_t *object);

#endif /* _XQC_MOQ_MESSAGE_WRITER_H_INCLUDED_ */
