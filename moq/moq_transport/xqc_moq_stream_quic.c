
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_conn.h"
#include "moq/moq_transport/xqc_moq_stream_quic.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "xquic/xquic.h"
#include <stdint.h>
#include <stdio.h>

static void *xqc_moq_quic_stream_create(void *conn, xqc_stream_direction_t dir, void *user_data);
static xqc_stream_t *xqc_moq_quic_stream(void *stream);
static xqc_int_t xqc_moq_quic_stream_close(void *stream);
static ssize_t xqc_moq_quic_stream_send(void *stream, uint8_t *send_data, size_t send_data_size, uint8_t fin);

static xqc_int_t xqc_moq_quic_stream_create_notify(xqc_stream_t *stream, void *user_data);
static xqc_int_t xqc_moq_quic_stream_close_notify(xqc_stream_t *stream, void *user_data);
static void xqc_moq_quic_stream_closing_notify(xqc_stream_t *stream, xqc_int_t err_code, void *user_data);
static xqc_int_t xqc_moq_quic_stream_read_notify(xqc_stream_t *stream, void *user_data);
static xqc_int_t xqc_moq_quic_stream_write_notify(xqc_stream_t *stream, void *user_data);
static xqc_int_t xqc_moq_quic_stream_create_v11_notify(xqc_stream_t *stream, void *user_data);
static xqc_int_t xqc_moq_quic_stream_create_v05_notify(xqc_stream_t *stream, void *user_data);

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

const xqc_stream_callbacks_t xqc_moq_quic_stream_callbacks_v11 = {
    .stream_create_notify  = xqc_moq_quic_stream_create_v11_notify,
    .stream_write_notify   = xqc_moq_quic_stream_write_notify,
    .stream_read_notify    = xqc_moq_quic_stream_read_notify,
    .stream_close_notify   = xqc_moq_quic_stream_close_notify,
    .stream_closing_notify = xqc_moq_quic_stream_closing_notify,
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
    session->version = XQC_MOQ_VERSION_DRAFT_05;
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
    moq_stream->stream_type = xqc_moq_stream_get_type(moq_stream);
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

static int
xqc_moq_quic_stream_create_v11_notify(xqc_stream_t *stream, void *user_data)
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
    if(session == NULL) {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|user_session->session is NULL|user_session:%p|",
                user_session);
        return -XQC_ENULLPTR;
    }
    // TODO setup version to draft-12 for test
    session->version = XQC_MOQ_CUR_VERSION;
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
    moq_stream->stream_type = xqc_moq_stream_get_type(moq_stream);
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
