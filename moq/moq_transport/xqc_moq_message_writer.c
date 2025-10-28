#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/xqc_moq.h"

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
xqc_moq_msg_encode_object_datagram_len(xqc_moq_object_datagram_t *object_datagram)
{
    xqc_int_t len = 0;
    len += xqc_put_varint_len(object_datagram->type);
    len += xqc_put_varint_len(object_datagram->track_alias);
    len += xqc_put_varint_len(object_datagram->group_id);
    len += xqc_put_varint_len(object_datagram->object_id);
    len += xqc_put_varint_len(object_datagram->publisher_priority);
    
    // 仅当 Extensions Present 时才包含 Extension Headers Length
    if (object_datagram->extensions_present) {
        len += xqc_put_varint_len(object_datagram->extension_headers_length);
        len += object_datagram->extension_headers_length;
    }
    
    // OBJECT_DATAGRAM 总是包含 payload
    len += object_datagram->payload_len;
    return len;
}

xqc_int_t
xqc_moq_msg_encode_object_datagram(xqc_moq_object_datagram_t *object_datagram, uint8_t *buf, size_t buf_cap)
{
    uint8_t *p = buf;
    p = xqc_put_varint(p, object_datagram->type);
    p = xqc_put_varint(p, object_datagram->track_alias);
    p = xqc_put_varint(p, object_datagram->group_id);
    p = xqc_put_varint(p, object_datagram->object_id);
    p = xqc_put_varint(p, object_datagram->publisher_priority);
    
    // 仅当 Extensions Present 时才包含 Extension Headers Length
    if (object_datagram->extensions_present) {
        p = xqc_put_varint(p, object_datagram->extension_headers_length);
        if (object_datagram->extension_headers_length > 0) {
            memcpy(p, object_datagram->extension_headers, object_datagram->extension_headers_length);
            p += object_datagram->extension_headers_length;
        }
    }
    
    // OBJECT_DATAGRAM 总是包含 payload
    memcpy(p, object_datagram->payload, object_datagram->payload_len);
    p += object_datagram->payload_len;
    return p - buf;
}


xqc_int_t
xqc_moq_write_object_datagram(xqc_moq_session_t *session, 
    uint64_t track_alias, uint64_t group_id, uint64_t object_id, uint8_t publisher_priority, uint8_t *payload, size_t payload_len)
{
    xqc_connection_t *conn = xqc_moq_session_quic_conn(session);
    xqc_int_t encode_len = 0;
    xqc_int_t ret = 0;
    
    if (session == NULL ) {
        return -XQC_EPARAM;
    }

    xqc_moq_object_datagram_t *object_datagram = xqc_malloc(sizeof(xqc_moq_object_datagram_t));
    if (object_datagram == NULL) {
        return -XQC_EMALLOC;
    }
    
    // 初始化结构体
    xqc_memset(object_datagram, 0, sizeof(xqc_moq_object_datagram_t));
    
    // 设置基本类型为 OBJECT_DATAGRAM (0x0) - 无扩展，非组结束
    object_datagram->type = XQC_MOQ_OBJECT_DATAGRAM;
    object_datagram->extensions_present = XQC_FALSE;
    object_datagram->end_of_group = XQC_FALSE;
    
    object_datagram->track_alias = track_alias;
    object_datagram->group_id = group_id;
    object_datagram->object_id = object_id;
    object_datagram->publisher_priority = publisher_priority;
    object_datagram->payload = payload;
    object_datagram->payload_len = payload_len;

    encode_len = xqc_moq_msg_encode_object_datagram_len(object_datagram);
    xqc_log(session->log, XQC_LOG_DEBUG, "|moq_obj_encode_len|len:%d|", encode_len);
    if (encode_len > XQC_MOQ_MAX_OBJECT_LEN) {
        xqc_log(session->log, XQC_LOG_ERROR, "|moq_obj_encode_oversize|len:%d|max:%d|", encode_len, XQC_MOQ_MAX_OBJECT_LEN);
        xqc_moq_msg_free_object_datagram(object_datagram);
        return -XQC_ELIMIT;
    }

    uint8_t *data = xqc_calloc(1, encode_len);
    if (data == NULL) {
        xqc_moq_msg_free_object_datagram(object_datagram);
        return -XQC_EMALLOC;
    }
    
    ret = xqc_moq_msg_encode_object_datagram(object_datagram, data, encode_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode msg error|ret:%d|", ret);
        xqc_free(data);
        xqc_moq_msg_free_object_datagram(object_datagram);
        return ret;
    }

    ret = xqc_datagram_send(conn, data, encode_len, NULL, XQC_DATA_QOS_HIGHEST);
    if(ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_datagram_send error|ret:%d|", ret);
        xqc_free(data);
        xqc_moq_msg_free_object_datagram(object_datagram);
        return ret;
    }

    xqc_free(data);
    xqc_moq_msg_free_object_datagram(object_datagram);
    return XQC_OK;
}

void xqc_moq_msg_free_object_datagram(xqc_moq_object_datagram_t *object_datagram)
{
    if(object_datagram != NULL) {
        xqc_free(object_datagram);
    }
}

xqc_int_t
xqc_moq_write_msg_generic(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_msg_base_t *msg_base, xqc_moq_msg_init_handler_pt init_handler)
{
    init_handler(msg_base, session);
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
xqc_moq_write_subscribe_v05(xqc_moq_session_t *session, xqc_moq_subscribe_msg_t_v05 *subscribe)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &subscribe->msg_base,
                                     xqc_moq_msg_subscribe_init_handler);
}

xqc_int_t
xqc_moq_write_subscribe_v13(xqc_moq_session_t *session, xqc_moq_subscribe_msg_t_v13 *subscribe)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &subscribe->msg_base,
                                     xqc_moq_msg_subscribe_init_handler);
}

xqc_int_t
xqc_moq_write_unsubscribe(xqc_moq_session_t *session, xqc_moq_unsubscribe_msg_t *unsubscribe)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &unsubscribe->msg_base,
                                     xqc_moq_msg_unsubscribe_init_handler);
}

xqc_int_t
xqc_moq_write_subscribe_update_v05(xqc_moq_session_t *session, xqc_moq_subscribe_update_msg_t_v05 *update)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &update->msg_base,
                                     xqc_moq_msg_subscribe_update_init_handler);
}

xqc_int_t
xqc_moq_write_subscribe_update_v13(xqc_moq_session_t *session, xqc_moq_subscribe_update_msg_t_v13 *update)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &update->msg_base,
                                     xqc_moq_msg_subscribe_update_init_handler);
}

xqc_int_t
xqc_moq_write_subscribe_ok(xqc_moq_session_t *session, xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    printf("msg report: write subscribe ok\n");
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

xqc_int_t 
xqc_moq_write_subgroup_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_subgroup_msg_t *subgroup)
{
    xqc_int_t ret = xqc_moq_write_msg_generic(session,stream,&subgroup->msg_base,
                                     xqc_moq_msg_subgroup_init_handler);
    if (ret < 0) {
        return ret;
    }
    return ret;
}

xqc_int_t
xqc_moq_write_subgroup_object_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_subgroup_object_msg_t *object)
{
    return xqc_moq_write_msg_generic(session, stream, &object->msg_base,
                                     xqc_moq_msg_subgroup_object_init_handler);
}

xqc_int_t
xqc_moq_write_announce_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_announce_msg_t *announce)
{
    return xqc_moq_write_msg_generic(session, stream, &announce->msg_base,
                                     xqc_moq_msg_announce_init_handler);
}

xqc_int_t
xqc_moq_write_announce_ok_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_announce_ok_msg_t *announce_ok)
{
    return xqc_moq_write_msg_generic(session, stream, &announce_ok->msg_base,
                                     xqc_moq_msg_announce_ok_init_handler);
}

xqc_int_t
xqc_moq_write_fetch_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_fetch_msg_t *fetch)
{
    return xqc_moq_write_msg_generic(session, stream, &fetch->msg_base,
                                     xqc_moq_msg_fetch_init_handler);
}

xqc_int_t
xqc_moq_write_subscribe_done_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_subscribe_done_msg_t *subscribe_done)
{
    return xqc_moq_write_msg_generic(session, stream, &subscribe_done->msg_base,
                                     xqc_moq_msg_subscribe_done_init_handler);
}

xqc_int_t
xqc_moq_write_track_status_msg(xqc_moq_session_t *session, xqc_moq_track_status_msg_t *track_status)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &track_status->msg_base,
                                     xqc_moq_msg_track_status_init_handler);
}

xqc_int_t
xqc_moq_write_track_status_ok_msg(xqc_moq_session_t *session, xqc_moq_track_status_ok_msg_t *track_status_ok)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &track_status_ok->msg_base,
                                     xqc_moq_msg_track_status_ok_init_handler);
}

xqc_int_t
xqc_moq_write_track_status_error_msg(xqc_moq_session_t *session, xqc_moq_track_status_error_msg_t *track_status_error)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &track_status_error->msg_base,
                                     xqc_moq_msg_track_status_error_init_handler);
}

xqc_int_t
xqc_moq_msg_write_goaway(xqc_moq_session_t *session, xqc_moq_stream_t *stream, xqc_moq_goaway_msg_t *goaway)
{
    return xqc_moq_write_msg_generic(session, stream, &goaway->msg_base,
                                     xqc_moq_msg_goaway_init_handler);
}

xqc_int_t
xqc_moq_msg_write_subscribe_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
                                   xqc_moq_subscribe_namespace_msg_t *subscribe_namespace)
{
    return xqc_moq_write_msg_generic(session, stream, &subscribe_namespace->msg_base,
                                     xqc_moq_msg_subscribe_namespace_init_handler);
}

xqc_int_t
xqc_moq_msg_write_publish_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_publish_namespace_msg_t *publish_ns)
{
    return xqc_moq_write_msg_generic(session, stream, &publish_ns->msg_base,
                                     xqc_moq_msg_publish_namespace_init_handler);
}

xqc_int_t
xqc_moq_msg_write_publish_namespace_done(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_publish_namespace_done_msg_t *publish_ns_done)
{
    return xqc_moq_write_msg_generic(session, stream, &publish_ns_done->msg_base,
                                     xqc_moq_msg_publish_namespace_done_init_handler);
}

xqc_int_t
xqc_moq_write_subscribe_namespace_ok_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
                                         xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok)
{
    return xqc_moq_write_msg_generic(session, stream, &subscribe_namespace_ok->msg_base,
                                     xqc_moq_msg_subscribe_namespace_ok_init_handler);
}

xqc_int_t
xqc_moq_write_publish_msg(xqc_moq_session_t *session, xqc_moq_publish_msg_t *publish)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &publish->msg_base,
                                     xqc_moq_msg_publish_init_handler);
}

xqc_int_t
xqc_moq_write_publish_ok_msg(xqc_moq_session_t *session, xqc_moq_publish_ok_msg_t *publish_ok)
{
    printf("[DEBUG] xqc_moq_write_publish_ok_msg called, request_id=%llu\n", 
           (unsigned long long)publish_ok->request_id);
    
    xqc_int_t ret = xqc_moq_write_msg_generic(session, session->ctl_stream, &publish_ok->msg_base,
                                               xqc_moq_msg_publish_ok_init_handler);
    printf("[DEBUG] xqc_moq_write_msg_generic returned: %d\n", ret);
    return ret;
}

xqc_int_t
xqc_moq_write_unsubscribe_namespace_msg(xqc_moq_session_t *session, xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &unsubscribe_namespace->msg_base,
                                     xqc_moq_msg_unsubscribe_namespace_init_handler);
}

xqc_int_t
xqc_moq_msg_encode_object_datagram_len_ext(xqc_moq_object_datagram_t *object_datagram)
{
    xqc_int_t len = 0;
    len += xqc_put_varint_len(object_datagram->type);
    len += xqc_put_varint_len(object_datagram->track_alias);
    len += xqc_put_varint_len(object_datagram->group_id);
    len += xqc_put_varint_len(object_datagram->object_id);
    len += xqc_put_varint_len(object_datagram->publisher_priority);
    
    /* 仅当 Extensions Present 时才包含 Extension Headers */
    if (object_datagram->extensions_present) {
        len += xqc_put_varint_len(object_datagram->extension_headers_length);
        len += object_datagram->extension_headers_length;
    }
    
    len += object_datagram->payload_len;
    return len;
}

/* 改进的 OBJECT_DATAGRAM 编码函数 */
xqc_int_t
xqc_moq_msg_encode_object_datagram_ext(xqc_moq_object_datagram_t *object_datagram, uint8_t *buf, size_t buf_cap)
{
    uint8_t *p = buf;
    p = xqc_put_varint(p, object_datagram->type);
    p = xqc_put_varint(p, object_datagram->track_alias);
    p = xqc_put_varint(p, object_datagram->group_id);
    p = xqc_put_varint(p, object_datagram->object_id);
    p = xqc_put_varint(p, object_datagram->publisher_priority);
    
    /* 仅当 Extensions Present 时才包含 Extension Headers */
    if (object_datagram->extensions_present) {
        p = xqc_put_varint(p, object_datagram->extension_headers_length);
        if (object_datagram->extension_headers_length > 0) {
            memcpy(p, object_datagram->extension_headers, object_datagram->extension_headers_length);
            p += object_datagram->extension_headers_length;
        }
    }
    
    if (object_datagram->payload_len > 0) {
        memcpy(p, object_datagram->payload, object_datagram->payload_len);
        p += object_datagram->payload_len;
    }
    
    return p - buf;
}

xqc_int_t
xqc_moq_msg_encode_object_datagram_status_len(xqc_moq_object_datagram_status_t *object_datagram_status)
{
    xqc_int_t len = 0;
    len += xqc_put_varint_len(object_datagram_status->type);
    len += xqc_put_varint_len(object_datagram_status->track_alias);
    len += xqc_put_varint_len(object_datagram_status->group_id);
    len += xqc_put_varint_len(object_datagram_status->object_id);
    len += xqc_put_varint_len(object_datagram_status->publisher_priority);
    
    // 仅当 Extensions 存在时才包含 Extension Headers Length
    if (object_datagram_status->extensions_present) {
        len += xqc_put_varint_len(object_datagram_status->extension_headers_length);
        len += object_datagram_status->extension_headers_length;
    }
    
    len += xqc_put_varint_len(object_datagram_status->object_status);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_object_datagram_status(xqc_moq_object_datagram_status_t *object_datagram_status, uint8_t *buf, size_t buf_cap)
{
    uint8_t *p = buf;
    p = xqc_put_varint(p, object_datagram_status->type);
    p = xqc_put_varint(p, object_datagram_status->track_alias);
    p = xqc_put_varint(p, object_datagram_status->group_id);
    p = xqc_put_varint(p, object_datagram_status->object_id);
    p = xqc_put_varint(p, object_datagram_status->publisher_priority);
    
    // 仅当 Extensions 存在时才包含 Extension Headers Length
    if (object_datagram_status->extensions_present) {
        p = xqc_put_varint(p, object_datagram_status->extension_headers_length);
        if (object_datagram_status->extension_headers_length > 0) {
            memcpy(p, object_datagram_status->extension_headers, object_datagram_status->extension_headers_length);
            p += object_datagram_status->extension_headers_length;
        }
    }
    
    p = xqc_put_varint(p, object_datagram_status->object_status);
    return p - buf;
}

xqc_int_t
xqc_moq_write_object_datagram_ext(xqc_moq_session_t *session, xqc_moq_object_datagram_t *object_datagram)
{
    xqc_connection_t *conn = xqc_moq_session_quic_conn(session);
    xqc_int_t encode_len = 0;
    xqc_int_t ret = 0;
    
    if (session == NULL || object_datagram == NULL) {
        return -XQC_EPARAM;
    }

    // 根据标准设置 OBJECT_DATAGRAM Type (0x0-0x3)
    if (object_datagram->extensions_present) {
        if (object_datagram->end_of_group) {
            object_datagram->type = XQC_MOQ_OBJECT_DATAGRAM_EOG_EXT;  // 0x3
        } else {
            object_datagram->type = XQC_MOQ_OBJECT_DATAGRAM_EXT;      // 0x1
        }
    } else {
        if (object_datagram->end_of_group) {
            object_datagram->type = XQC_MOQ_OBJECT_DATAGRAM_EOG;      // 0x2
        } else {
            object_datagram->type = XQC_MOQ_OBJECT_DATAGRAM;          // 0x0
        }
    }

    encode_len = xqc_moq_msg_encode_object_datagram_len_ext(object_datagram);
    xqc_log(session->log, XQC_LOG_DEBUG, "|encode_len:%d|", encode_len);
    if (encode_len > XQC_MOQ_MAX_OBJECT_LEN) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode_len > XQC_MOQ_MAX_OBJECT_LEN|ret:%d|", encode_len);
        return -XQC_ELIMIT;
    }

    uint8_t *data = xqc_calloc(1, encode_len);
    if (data == NULL) {
        return -XQC_EMALLOC;
    }

    ret = xqc_moq_msg_encode_object_datagram_ext(object_datagram, data, encode_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode msg error|ret:%d|", ret);
        xqc_free(data);
        return ret;
    }

    ret = xqc_datagram_send(conn, data, encode_len, NULL, XQC_DATA_QOS_HIGHEST);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_datagram_send error|ret:%d|", ret);
        xqc_free(data);
        return ret;
    }

    xqc_free(data);
    return XQC_OK;
}

xqc_int_t
xqc_moq_write_object_datagram_status(xqc_moq_session_t *session, xqc_moq_object_datagram_status_t *object_datagram_status)
{
    xqc_connection_t *conn = xqc_moq_session_quic_conn(session);
    xqc_int_t encode_len = 0;
    xqc_int_t ret = 0;
    
    if (session == NULL || object_datagram_status == NULL) {
        return -XQC_EPARAM;
    }

    // 根据标准设置 OBJECT_DATAGRAM_STATUS Type (0x4-0x5)
    if (object_datagram_status->extensions_present) {
        object_datagram_status->type = XQC_MOQ_OBJECT_DATAGRAM_STATUS_EXT;  // 0x5
    } else {
        object_datagram_status->type = XQC_MOQ_OBJECT_DATAGRAM_STATUS;      // 0x4
    }

    encode_len = xqc_moq_msg_encode_object_datagram_status_len(object_datagram_status);
    xqc_log(session->log, XQC_LOG_DEBUG, "|encode_len:%d|", encode_len);
    if (encode_len > XQC_MOQ_MAX_OBJECT_LEN) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode_len > XQC_MOQ_MAX_OBJECT_LEN|ret:%d|", encode_len);
        return -XQC_ELIMIT;
    }

    uint8_t *data = xqc_calloc(1, encode_len);
    if (data == NULL) {
        return -XQC_EMALLOC;
    }

    ret = xqc_moq_msg_encode_object_datagram_status(object_datagram_status, data, encode_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode msg error|ret:%d|", ret);
        xqc_free(data);
        return ret;
    }

    ret = xqc_datagram_send(conn, data, encode_len, NULL, XQC_DATA_QOS_HIGHEST);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_datagram_send error|ret:%d|", ret);
        xqc_free(data);
        return ret;
    }

    xqc_free(data);
    return XQC_OK;
}

void xqc_moq_msg_free_object_datagram_status(xqc_moq_object_datagram_status_t *object_datagram_status)
{
    if (object_datagram_status != NULL) {
        if (object_datagram_status->extension_headers != NULL) {
            xqc_free(object_datagram_status->extension_headers);
        }
        xqc_free(object_datagram_status);
    }
}