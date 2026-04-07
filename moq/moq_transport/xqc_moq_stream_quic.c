
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_conn.h"
#include "moq/moq_transport/xqc_moq_stream_quic.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"

static void *xqc_moq_quic_stream_create(void *conn, xqc_stream_direction_t dir, void *user_data);
static xqc_stream_t *xqc_moq_quic_stream(void *stream);
static xqc_int_t xqc_moq_quic_stream_close(void *stream);
static ssize_t xqc_moq_quic_stream_send(void *stream, uint8_t *send_data, size_t send_data_size, uint8_t fin);

static xqc_int_t xqc_moq_quic_stream_create_notify(xqc_stream_t *stream, void *user_data);
static xqc_int_t xqc_moq_quic_stream_close_notify(xqc_stream_t *stream, void *user_data);
static void xqc_moq_quic_stream_closing_notify(xqc_stream_t *stream, xqc_int_t err_code, void *user_data);
static xqc_int_t xqc_moq_quic_stream_read_notify(xqc_stream_t *stream, void *user_data);
static xqc_int_t xqc_moq_quic_stream_write_notify(xqc_stream_t *stream, void *user_data);

static void xqc_moq_quic_datagram_read_notify(xqc_connection_t *conn, void *user_data,
    const void *data, size_t data_len, uint64_t unix_ts);
static void xqc_moq_quic_datagram_write_notify(xqc_connection_t *conn, void *user_data);
static xqc_int_t xqc_moq_quic_datagram_lost_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data);
static void xqc_moq_quic_datagram_acked_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data);
static void xqc_moq_quic_datagram_mss_updated_notify(xqc_connection_t *conn, size_t mss, void *user_data);

const xqc_moq_trans_stream_ops_t xqc_moq_quic_stream_ops = {
    .create      = xqc_moq_quic_stream_create,
    .quic_stream = xqc_moq_quic_stream,
    .close       = xqc_moq_quic_stream_close,
    .write       = xqc_moq_quic_stream_send,
};

const xqc_stream_callbacks_t xqc_moq_quic_stream_callbacks = {
    .stream_create_notify  = xqc_moq_quic_stream_create_notify,
    .stream_write_notify   = xqc_moq_quic_stream_write_notify,
    .stream_read_notify    = xqc_moq_quic_stream_read_notify,
    .stream_close_notify   = xqc_moq_quic_stream_close_notify,
    .stream_closing_notify = xqc_moq_quic_stream_closing_notify,
};

const xqc_datagram_callbacks_t xqc_moq_quic_datagram_callbacks = {
    .datagram_read_notify        = xqc_moq_quic_datagram_read_notify,
    .datagram_write_notify       = xqc_moq_quic_datagram_write_notify,
    .datagram_acked_notify       = xqc_moq_quic_datagram_acked_notify,
    .datagram_lost_notify        = xqc_moq_quic_datagram_lost_notify,
    .datagram_mss_updated_notify = xqc_moq_quic_datagram_mss_updated_notify,
};

static void *
xqc_moq_quic_stream_create(void *conn, xqc_stream_direction_t dir, void *user_data)
{
    xqc_connection_t *quic_conn = (xqc_connection_t *)conn;
    return xqc_stream_create_with_direction(quic_conn, dir, user_data);
}

static xqc_stream_t *
xqc_moq_quic_stream(void *stream)
{
    xqc_stream_t *quic_stream = (xqc_stream_t *)stream;
    return quic_stream;
}

static xqc_int_t
xqc_moq_quic_stream_close(void *stream)
{
    xqc_stream_t *quic_stream = (xqc_stream_t *)stream;
    return xqc_stream_close(quic_stream);
}

static ssize_t
xqc_moq_quic_stream_send(void *stream, uint8_t *send_data, size_t send_data_size, uint8_t fin)
{
    xqc_stream_t *quic_stream = (xqc_stream_t *)stream;
    return xqc_stream_send(quic_stream, send_data, send_data_size, fin);
}

static xqc_int_t
xqc_moq_quic_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    if (user_data != NULL) {
        return XQC_OK;
    }

    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)xqc_get_conn_user_data_by_stream(stream);
    if (user_session == NULL) {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|user session is NULL|");
        return -XQC_ENULLPTR;
    }
    xqc_moq_session_t *session = user_session->session;
    if (session == NULL) {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|session is NULL|user_session:%p|",
                user_session);
        return -XQC_ENULLPTR;
    }

    xqc_moq_stream_t *moq_stream = xqc_moq_stream_create(session);
    if (moq_stream == NULL) {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|create moq stream error|");
        return -XQC_EMALLOC;
    }
    moq_stream->trans_stream = stream;
    xqc_stream_set_user_data(stream, moq_stream);

    if (xqc_get_stream_type(stream->stream_id) == XQC_CLI_BID) {
        if (session->ctl_stream == NULL) {
            session->ctl_stream = moq_stream;
        } else {
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|duplicate control stream|");
            return -XQC_EPROTO;
        }
    }

    return XQC_OK;
}

static xqc_int_t
xqc_moq_quic_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_moq_stream_t *moq_stream = (xqc_moq_stream_t*)user_data;

    xqc_moq_stream_destroy(moq_stream);
    return XQC_OK;
}

static void
xqc_moq_quic_stream_closing_notify(xqc_stream_t *stream, xqc_int_t err_code, void *user_data)
{
    xqc_moq_stream_t *moq_stream = (xqc_moq_stream_t*)user_data;
}

static xqc_int_t
xqc_moq_quic_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_int_t ret = 0;
    xqc_moq_stream_t *moq_stream = (xqc_moq_stream_t *) user_data;
    ret = xqc_moq_stream_write(moq_stream);
    if (ret < 0) {
        xqc_log(moq_stream->session->log, XQC_LOG_ERROR, "|xqc_moq_stream_write error|ret:%d|", ret);
    }
    return XQC_OK;
}

static xqc_int_t
xqc_moq_quic_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_int_t ret = 0;
    uint8_t fin = 0;
    xqc_moq_stream_t *moq_stream = (xqc_moq_stream_t *) user_data;

    uint8_t buff[4096] = {0};
    size_t buff_size = 4096;
    ssize_t read;


    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;
        } else if (read < 0) {
            break;
        }

        /*DEBUG_PRINTF("stream recv:");
        for (int i = 0; i<read; i++) {
            DEBUG_PRINTF("0x%x ", buff[i]);
        }
        DEBUG_PRINTF("\n");*/

        ret = xqc_moq_stream_process(moq_stream, buff, read, fin);
        if (ret < 0) {
            return ret;
        }

    } while (read > 0 && !fin);

    return XQC_OK;
}

static void
xqc_moq_quic_datagram_read_notify(xqc_connection_t *conn, void *user_data,
    const void *data, size_t data_len, uint64_t unix_ts)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    if (user_session == NULL || user_session->session == NULL || data == NULL || data_len == 0) {
        return;
    }
    xqc_moq_session_t *session = user_session->session;

    xqc_moq_object_datagram_msg_t dgram;
    xqc_memzero(&dgram, sizeof(dgram));
    xqc_int_t ret = xqc_moq_object_datagram_decode((uint8_t *)data, data_len, &dgram);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|moq_datagram_decode error|ret:%d|len:%uz|", ret, data_len);
        if (ret == -XQC_EPROTO) {
            xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION, "invalid object datagram type");
        }
        xqc_moq_object_datagram_free_fields(&dgram);
        return;
    }

    xqc_moq_object_t object;
    xqc_memzero(&object, sizeof(object));
    object.subscribe_id = 0;
    object.track_alias = dgram.track_alias;
    object.group_id = dgram.group_id;
    object.object_id = dgram.object_id;
    object.subgroup_id = 0;
    object.object_id_delta = 0;
    object.send_order = 0;
    object.publisher_priority_set = 1;
    object.publisher_priority = dgram.publisher_priority;
    object.status = dgram.payload_len > 0 ? XQC_MOQ_OBJ_STATUS_NORMAL : dgram.status;
    object.ext_params_num = dgram.ext_params_num;
    object.ext_params = dgram.ext_params;
    object.payload = dgram.payload;
    object.payload_len = dgram.payload_len;
    object.custom_id_flag = 0;
    object.forwarding_preference = XQC_MOQ_FORWARDING_DATAGRAM;

    xqc_log(session->log, XQC_LOG_DEBUG,
            "|moq_datagram_recv|type:%ui|track_alias:%ui|group_id:%ui|object_id:%ui|prio:%ud|payload_len:%ui|",
            dgram.type, dgram.track_alias, dgram.group_id, dgram.object_id,
            dgram.publisher_priority, dgram.payload_len);

    xqc_moq_on_datagram_object(session, &object);
    xqc_moq_object_datagram_free_fields(&dgram);
}

static void
xqc_moq_quic_datagram_write_notify(xqc_connection_t *conn, void *user_data)
{
}

static xqc_int_t
xqc_moq_quic_datagram_lost_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    if (user_session && user_session->session) {
        xqc_log(user_session->session->log, XQC_LOG_DEBUG, "|moq_dgram_lost|dgram_id:%ui|", dgram_id);
    }
    return XQC_OK;
}

static void
xqc_moq_quic_datagram_acked_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    if (user_session && user_session->session) {
        xqc_log(user_session->session->log, XQC_LOG_DEBUG, "|moq_dgram_acked|dgram_id:%ui|", dgram_id);
    }
}

static void
xqc_moq_quic_datagram_mss_updated_notify(xqc_connection_t *conn, size_t mss, void *user_data)
{
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    if (user_session && user_session->session) {
        xqc_log(user_session->session->log, XQC_LOG_DEBUG, "|moq_dgram_mss_updated|mss:%z|", mss);
    }
}
