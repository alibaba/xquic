
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"

xqc_int_t
xqc_moq_msg_write(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t encode_len = 0;
    xqc_int_t ret = 0;
    
    if (session == NULL || stream == NULL || msg_base == NULL) {
        return -XQC_EPARAM;
    }

    encode_len = msg_base->encode_len(msg_base);
    if (encode_len > XQC_MOQ_MAX_OBJECT_LEN) {
        return -XQC_ELIMIT;
    }

    /* Last send not finished */
    if (stream->write_buf_processed != stream->write_buf_len) {
        stream->write_buf_cap += encode_len;
    } else {
        stream->write_buf_cap = encode_len;
        stream->write_buf_processed = 0;
        stream->write_buf_len = 0;
    }

    stream->write_buf = xqc_realloc(stream->write_buf, stream->write_buf_cap);
    ret = msg_base->encode(msg_base, stream->write_buf + stream->write_buf_len, stream->write_buf_cap - stream->write_buf_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode msg error|ret:%d|", ret);
        return ret;
    }
    stream->write_buf_len += ret;

    ret = xqc_moq_stream_write(stream);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_stream_write error|ret:%d|msg_type:0x%xi|", ret, msg_base->type());
        return ret;
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_write_msg_generic(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_msg_base_t *msg_base, xqc_moq_msg_init_handler_pt init_handler)
{
    init_handler(msg_base);
    return xqc_moq_msg_write(session, stream, msg_base);
}

xqc_int_t
xqc_moq_write_client_setup(xqc_moq_session_t *session, xqc_moq_client_setup_msg_t *client_setup)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &client_setup->msg_base,
                                     xqc_moq_msg_client_setup_init_handler);
}

xqc_int_t
xqc_moq_write_client_setup_v14(xqc_moq_session_t *session, xqc_moq_client_setup_v14_msg_t *client_setup,
    xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    if (client_setup && params && params_num > 0) {
        client_setup->params = params;
        client_setup->params_num = params_num;
    }
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &client_setup->msg_base,
                                     xqc_moq_msg_client_setup_v14_init_handler);
}

xqc_int_t
xqc_moq_write_server_setup(xqc_moq_session_t *session, xqc_moq_server_setup_msg_t *server_setup)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &server_setup->msg_base,
                                     xqc_moq_msg_server_setup_init_handler);
}

xqc_int_t
xqc_moq_write_server_setup_v14(xqc_moq_session_t *session, xqc_moq_server_setup_v14_msg_t *server_setup)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &server_setup->msg_base,
                                     xqc_moq_msg_server_setup_v14_init_handler);
}

xqc_int_t
xqc_moq_write_subscribe(xqc_moq_session_t *session, xqc_moq_subscribe_msg_t *subscribe)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &subscribe->msg_base,
                                     xqc_moq_msg_subscribe_init_handler);
}

xqc_int_t
xqc_moq_write_subscribe_update(xqc_moq_session_t *session, xqc_moq_subscribe_update_msg_t *update)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &update->msg_base,
                                     xqc_moq_msg_subscribe_update_init_handler);
}

xqc_int_t
xqc_moq_write_unsubscribe(xqc_moq_session_t *session, xqc_moq_unsubscribe_msg_t *unsubscribe)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &unsubscribe->msg_base,
                                     xqc_moq_msg_unsubscribe_init_handler);
}

xqc_int_t
xqc_moq_write_subscribe_ok(xqc_moq_session_t *session, xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &subscribe_ok->msg_base,
                                     xqc_moq_msg_subscribe_ok_init_handler);
}

xqc_int_t
xqc_moq_write_subscribe_error(xqc_moq_session_t *session, xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &subscribe_error->msg_base,
                                     xqc_moq_msg_subscribe_error_init_handler);
}

xqc_int_t
xqc_moq_write_publish(xqc_moq_session_t *session, xqc_moq_publish_msg_t *publish)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &publish->msg_base,
                                     xqc_moq_msg_publish_init_handler);
}

xqc_int_t
xqc_moq_write_publish_ok(xqc_moq_session_t *session, xqc_moq_publish_ok_msg_t *publish_ok)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &publish_ok->msg_base,
                                     xqc_moq_msg_publish_ok_init_handler);
}

xqc_int_t
xqc_moq_write_publish_error(xqc_moq_session_t *session, xqc_moq_publish_error_msg_t *publish_error)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &publish_error->msg_base,
                                     xqc_moq_msg_publish_error_init_handler);
}

xqc_int_t
xqc_moq_write_publish_done(xqc_moq_session_t *session, xqc_moq_publish_done_msg_t *publish_done)
{
    if (session == NULL || publish_done == NULL) {
        return -XQC_EPARAM;
    }

    if (publish_done->stream_count == 0) {
        xqc_moq_track_t *track = xqc_moq_find_track_by_subscribe_id(session,
            publish_done->subscribe_id, XQC_MOQ_TRACK_FOR_PUB);
        if (track && track->streams_count > 0) {
            publish_done->stream_count = track->streams_count;
        } else {
            publish_done->stream_count = ((uint64_t)1 << 62) - 1;
        }
    }

    return xqc_moq_write_msg_generic(session, session->ctl_stream, &publish_done->msg_base,
                                     xqc_moq_msg_publish_done_init_handler);
}

xqc_int_t
xqc_moq_write_object_stream_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_object_stream_msg_t *object)
{
    return xqc_moq_write_msg_generic(session, stream, &object->msg_base,
                                     xqc_moq_msg_object_stream_init_handler);
}

xqc_int_t
xqc_moq_write_subgroup_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_subgroup_msg_t *object)
{
    return xqc_moq_write_msg_generic(session, stream, &object->msg_base,
                                     xqc_moq_msg_subgroup_init_handler);
}

xqc_int_t
xqc_moq_write_stream_header_track_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_stream_header_track_msg_t *track_header)
{
    return xqc_moq_write_msg_generic(session, stream, &track_header->msg_base,
                                     xqc_moq_msg_track_header_init_handler);
}

xqc_int_t
xqc_moq_write_track_stream_obj_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_track_stream_obj_msg_t *object)
{
    return xqc_moq_write_msg_generic(session, stream, &object->msg_base,
                                     xqc_moq_msg_track_stream_obj_init_handler);
}

xqc_int_t
xqc_moq_send_subgroup(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_subgroup_object_t *subgroup)
{
    if (session == NULL || track == NULL || subgroup == NULL) {
        return -XQC_EPARAM;
    }

    if (subgroup->payload_len > XQC_MOQ_MAX_OBJECT_LEN) {
        return -XQC_ELIMIT;
    }

    xqc_moq_stream_t *stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if (stream == NULL) {
        return -XQC_ECREATE_STREAM;
    }
    stream->write_stream_fin = 1;

    xqc_moq_object_stream_msg_t object;
    xqc_memzero(&object, sizeof(object));
    object.subscribe_id = subgroup->subscribe_id;
    object.track_alias = subgroup->track_alias;
    object.group_id = subgroup->group_id;
    object.object_id = subgroup->object_id;
    object.subgroup_id = subgroup->subgroup_id;
    object.object_id_delta = subgroup->object_id_delta ? subgroup->object_id_delta : subgroup->object_id;
    object.subgroup_type = subgroup->subgroup_type ? subgroup->subgroup_type : XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    object.subgroup_priority = subgroup->subgroup_priority;
    object.send_order = subgroup->send_order;
    object.status = subgroup->status;
    object.payload = (uint8_t *)subgroup->payload;
    object.payload_len = subgroup->payload_len;

    if (object.subgroup_type == 0) {
        object.subgroup_type = XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    }
    if (object.subgroup_priority == 0) {
        object.subgroup_priority = XQC_MOQ_DEFAULT_SUBGROUP_PRIORITY;
    }
    if (object.object_id_delta == 0) {
        object.object_id_delta = object.object_id;
    }

    xqc_moq_stream_on_track_write(stream, track, object.group_id, object.object_id, 0);

    xqc_int_t ret = xqc_moq_write_subgroup_msg(session, stream, &object);
    if (ret < 0) {
        xqc_moq_stream_close(stream);
        return ret;
    }
    return ret;
}
