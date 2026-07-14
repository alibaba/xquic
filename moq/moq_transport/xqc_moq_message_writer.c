
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
xqc_moq_write_server_setup(xqc_moq_session_t *session, xqc_moq_server_setup_msg_t *server_setup)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &server_setup->msg_base,
                                     xqc_moq_msg_server_setup_init_handler);
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
xqc_moq_write_object_stream_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_object_stream_msg_t *object)
{
    return xqc_moq_write_msg_generic(session, stream, &object->msg_base,
                                     xqc_moq_msg_object_stream_init_handler);
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