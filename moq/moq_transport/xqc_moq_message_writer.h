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

xqc_int_t xqc_moq_write_subscribe_v05(xqc_moq_session_t *session, xqc_moq_subscribe_msg_t_v05 *subscribe);

xqc_int_t xqc_moq_write_subscribe_v13(xqc_moq_session_t *session, xqc_moq_subscribe_msg_t_v13 *subscribe);

xqc_int_t xqc_moq_write_unsubscribe(xqc_moq_session_t *session, xqc_moq_unsubscribe_msg_t *unsubscribe);

xqc_int_t xqc_moq_write_subscribe_update_v05(xqc_moq_session_t *session, xqc_moq_subscribe_update_msg_t_v05 *update);

xqc_int_t xqc_moq_write_subscribe_update_v13(xqc_moq_session_t *session, xqc_moq_subscribe_update_msg_t_v13 *update);

xqc_int_t xqc_moq_write_object_stream_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_object_stream_msg_t *object);

xqc_int_t xqc_moq_write_stream_header_track_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_stream_header_track_msg_t *track_header);

xqc_int_t xqc_moq_write_track_stream_obj_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_track_stream_obj_msg_t *object);

xqc_int_t xqc_moq_write_subgroup_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_subgroup_msg_t *track_subgroup);

xqc_int_t xqc_moq_write_subgroup_object_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_subgroup_object_msg_t *subgroup_object);

xqc_int_t xqc_moq_write_announce_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_announce_msg_t *announce);

xqc_int_t xqc_moq_write_announce_ok_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_announce_ok_msg_t *announce_ok);

xqc_int_t xqc_moq_msg_write_subscribe_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
                                             xqc_moq_subscribe_namespace_msg_t *subscribe_namespace);

xqc_int_t xqc_moq_write_subscribe_namespace_ok_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
                                                   xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok);
xqc_int_t xqc_moq_msg_write_publish_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_publish_namespace_msg_t *publish_ns);

xqc_int_t xqc_moq_msg_write_publish_namespace_done(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_publish_namespace_done_msg_t *publish_ns_done);

xqc_int_t xqc_moq_write_unsubscribe_namespace_msg(xqc_moq_session_t *session,
     xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace);

xqc_int_t xqc_moq_write_fetch_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_fetch_msg_t *fetch);

xqc_int_t xqc_moq_write_subscribe_done_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_subscribe_done_msg_t *subscribe_done);

xqc_int_t xqc_moq_write_track_status_msg(xqc_moq_session_t *session, xqc_moq_track_status_msg_t *track_status);

xqc_int_t xqc_moq_write_track_status_ok_msg(xqc_moq_session_t *session, xqc_moq_track_status_ok_msg_t *track_status_ok);

xqc_int_t xqc_moq_write_track_status_error_msg(xqc_moq_session_t *session, xqc_moq_track_status_error_msg_t *track_status_error);

xqc_int_t xqc_moq_msg_write_goaway(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_goaway_msg_t *goaway);

xqc_int_t xqc_moq_msg_encode_object_datagram_len(xqc_moq_object_datagram_t *object_datagram);

xqc_int_t xqc_moq_msg_encode_object_datagram(xqc_moq_object_datagram_t *object_datagram, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_encode_object_datagram_status_len(xqc_moq_object_datagram_status_t *object_datagram_status);

xqc_int_t xqc_moq_msg_encode_object_datagram_status(xqc_moq_object_datagram_status_t *object_datagram_status, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_write_object_datagram_ext(xqc_moq_session_t *session, xqc_moq_object_datagram_t *object_datagram);

xqc_int_t xqc_moq_write_object_datagram_status(xqc_moq_session_t *session, xqc_moq_object_datagram_status_t *object_datagram_status);

xqc_int_t xqc_moq_write_publish_msg(xqc_moq_session_t *session, xqc_moq_publish_msg_t *publish);

xqc_int_t xqc_moq_write_publish_ok_msg(xqc_moq_session_t *session, xqc_moq_publish_ok_msg_t *publish_ok);

void xqc_moq_msg_free_object_datagram_status(xqc_moq_object_datagram_status_t *object_datagram_status);

#endif /* _XQC_MOQ_MESSAGE_WRITER_H_INCLUDED_ */
