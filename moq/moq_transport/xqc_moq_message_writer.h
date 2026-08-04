#ifndef _XQC_MOQ_MESSAGE_WRITER_H_INCLUDED_
#define _XQC_MOQ_MESSAGE_WRITER_H_INCLUDED_

#include "moq/xqc_moq.h"
#include "moq/moq_transport/xqc_moq_message.h"

xqc_int_t xqc_moq_msg_write(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_write_msg_generic(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_msg_base_t *msg_base, xqc_moq_semantic_id_t semantic);

xqc_int_t xqc_moq_write_client_setup(xqc_moq_session_t *session, xqc_moq_client_setup_msg_t *client_setup);

xqc_int_t xqc_moq_write_client_setup_v14(xqc_moq_session_t *session, xqc_moq_client_setup_v14_msg_t *client_setup,
    xqc_moq_message_parameter_t *params, uint64_t params_num);

xqc_int_t xqc_moq_write_client_setup_for_profile(
    xqc_moq_session_t *session,
    const xqc_moq_message_parameter_t *params, uint64_t params_num);

xqc_int_t xqc_moq_write_server_setup(xqc_moq_session_t *session, xqc_moq_server_setup_msg_t *server_setup);

xqc_int_t xqc_moq_write_server_setup_v14(xqc_moq_session_t *session, xqc_moq_server_setup_v14_msg_t *server_setup);

xqc_int_t xqc_moq_write_setup(xqc_moq_session_t *session,
    xqc_moq_setup_msg_t *setup);

xqc_int_t xqc_moq_write_server_setup_for_profile(
    xqc_moq_session_t *session,
    const xqc_moq_message_parameter_t *params, uint64_t params_num);

xqc_int_t xqc_moq_write_subscribe(xqc_moq_session_t *session, xqc_moq_subscribe_msg_t *subscribe);

xqc_int_t xqc_moq_write_subscribe_update(xqc_moq_session_t *session, xqc_moq_subscribe_update_msg_t *update);

xqc_int_t xqc_moq_write_unsubscribe(xqc_moq_session_t *session, xqc_moq_unsubscribe_msg_t *unsubscribe);

xqc_int_t xqc_moq_write_publish_namespace(xqc_moq_session_t *session,
    xqc_moq_publish_namespace_msg_t *publish_namespace);

xqc_int_t xqc_moq_write_request_ok(xqc_moq_session_t *session,
    uint64_t request_id, xqc_moq_request_ok_msg_t *request_ok);

xqc_int_t xqc_moq_write_request_error(xqc_moq_session_t *session,
    uint64_t request_id, xqc_moq_request_error_msg_t *request_error);

xqc_int_t xqc_moq_write_request_update(xqc_moq_session_t *session,
    uint64_t target_request_id, xqc_moq_request_update_msg_t *update);

xqc_int_t xqc_moq_write_fetch(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_fetch_msg_t *fetch);

xqc_int_t xqc_moq_write_track_status(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_track_status_msg_t *track_status);

xqc_int_t xqc_moq_write_fetch_ok(xqc_moq_session_t *session,
    uint64_t request_id, xqc_moq_fetch_ok_msg_t *fetch_ok);

xqc_int_t xqc_moq_write_fetch_header(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_fetch_header_msg_t *header,
    uint8_t fin);

xqc_int_t xqc_moq_write_fetch_object(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_object_t *object, uint8_t fin);

xqc_int_t xqc_moq_write_fetch_range_end(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, uint64_t group_id, uint64_t object_id,
    uint8_t unknown, uint8_t fin);

xqc_int_t xqc_moq_write_d18_update_failed_publish_done(
    xqc_moq_session_t *session, xqc_moq_stream_t *request_stream);

xqc_int_t xqc_moq_retry_d18_publish_done_after_data_fin(
    xqc_moq_stream_t *data_stream);

void xqc_moq_fail_d18_publish_done_after_data_write(
    xqc_moq_stream_t *data_stream);

xqc_int_t xqc_moq_write_publish_namespace_done(xqc_moq_session_t *session,
    xqc_moq_publish_namespace_done_msg_t *publish_namespace_done);

xqc_int_t xqc_moq_publish_namespace(xqc_moq_session_t *session,
    xqc_moq_publish_namespace_msg_t *publish_namespace);

xqc_int_t xqc_moq_publish_namespace_done(xqc_moq_session_t *session,
    xqc_moq_publish_namespace_done_msg_t *publish_namespace_done);

xqc_int_t xqc_moq_write_publish(xqc_moq_session_t *session, xqc_moq_publish_msg_t *publish);

xqc_int_t xqc_moq_write_publish_ok(xqc_moq_session_t *session, xqc_moq_publish_ok_msg_t *publish_ok);

xqc_int_t xqc_moq_write_publish_error(xqc_moq_session_t *session, xqc_moq_publish_error_msg_t *publish_error);

xqc_int_t xqc_moq_write_publish_done(xqc_moq_session_t *session, xqc_moq_publish_done_msg_t *publish_done);

xqc_int_t xqc_moq_write_object_stream_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_object_stream_msg_t *object);

xqc_int_t xqc_moq_write_subgroup_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_subgroup_msg_t *object);

xqc_int_t xqc_moq_append_subgroup_object(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_subgroup_msg_t *object);

xqc_int_t xqc_moq_write_stream_header_track_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_stream_header_track_msg_t *track_header);

xqc_int_t xqc_moq_write_track_stream_obj_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_track_stream_obj_msg_t *object);

xqc_int_t xqc_moq_send_object_datagram(xqc_moq_session_t *session, xqc_moq_object_t *object);

xqc_int_t xqc_moq_write_goaway(xqc_moq_session_t *session, const char *new_session_uri, size_t uri_len);

xqc_int_t xqc_moq_write_goaway_draft18(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, const char *uri, size_t uri_len,
    uint64_t timeout_ms, uint64_t request_id, uint8_t control_scope);

xqc_int_t xqc_moq_write_going_away_request_error(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream);

xqc_int_t xqc_moq_write_going_away_request_update_error(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream);

xqc_int_t xqc_moq_write_subscribe_namespace(xqc_moq_session_t *session,
    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace);

xqc_int_t xqc_moq_write_subscribe_tracks(xqc_moq_session_t *session,
    xqc_moq_subscribe_tracks_msg_t *subscribe_tracks);

xqc_int_t xqc_moq_write_publish_blocked(
    xqc_moq_session_t *session, uint64_t subscribe_tracks_request_id,
    const xqc_moq_track_ns_field_t *full_namespace,
    uint64_t full_namespace_num, const char *track_name,
    size_t track_name_len);

xqc_int_t xqc_moq_publish_blocked_stream_context_is_valid(
    const xqc_moq_stream_t *stream);

xqc_int_t xqc_moq_write_subscribe_namespace_ok(xqc_moq_session_t *session,
    xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok);

xqc_int_t xqc_moq_write_subscribe_namespace_error(xqc_moq_session_t *session,
    xqc_moq_subscribe_namespace_error_msg_t *subscribe_namespace_error);

xqc_int_t xqc_moq_write_namespace(xqc_moq_session_t *session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num);

xqc_int_t xqc_moq_write_namespace_done(xqc_moq_session_t *session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num);

xqc_int_t xqc_moq_write_unsubscribe_namespace(xqc_moq_session_t *session,
    xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace);

xqc_int_t xqc_moq_validate_full_track_name_for_write(xqc_moq_session_t *session,
    uint64_t track_namespace_num, const xqc_moq_track_ns_field_t *track_namespace_tuple,
    const char *track_name, size_t track_name_len);

xqc_int_t xqc_moq_validate_d18_full_track_name(
    uint64_t track_namespace_num,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    const char *track_name, size_t track_name_len);

#endif /* _XQC_MOQ_MESSAGE_WRITER_H_INCLUDED_ */
