/**
 * xqc_moq_stream_webtransport.c
 *
 * Thin adapter: implements xqc_moq_trans_stream_ops_t over WebTransport.
 * Mirrors xqc_moq_stream_quic.c structure, swapping raw QUIC stream
 * calls for WT bidistream/unistream APIs.
 */

#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_timer.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "xquic/xqc_webtransport.h"

/* retry interval for write-blocked streams (microseconds) */
#define XQC_MOQ_WT_WRITE_RETRY_INTERVAL     (50 * 1000)


/*
 * Wrapper around WT stream objects.  Holds the WT handle, stream direction
 * flag, and a retry timer for write-blocked conditions (WT has no
 * stream_write_notify callback like raw QUIC does).
 */
typedef struct xqc_moq_wt_stream_wrapper_s {
    xqc_stream_direction_t  dir;
    union {
        xqc_wt_bidistream_t *bidi;
        xqc_wt_unistream_t  *uni;
    } wt;
    xqc_moq_stream_t       *moq_stream;   /* back-pointer for timer cb */
    xqc_gp_timer_id_t       retry_timer_id;
} xqc_moq_wt_stream_wrapper_t;


/* ---- forward declarations ---- */

static void *xqc_moq_wt_stream_create(void *conn,
    xqc_stream_direction_t dir, void *user_data);
static xqc_stream_t *xqc_moq_wt_quic_stream(void *stream);
static xqc_int_t xqc_moq_wt_stream_close(void *stream);
static ssize_t xqc_moq_wt_stream_send(void *stream,
    uint8_t *send_data, size_t send_data_size, uint8_t fin);

static xqc_int_t xqc_moq_wt_bidi_create_notify(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *user_data);
static xqc_int_t xqc_moq_wt_bidi_read_notify(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t data_len, uint8_t fin, void *user_data);
static xqc_int_t xqc_moq_wt_bidi_close_notify(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *user_data);

static xqc_int_t xqc_moq_wt_uni_create_notify(
    xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *user_data);
static xqc_int_t xqc_moq_wt_uni_read_notify(
    xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t data_len, uint8_t fin, void *user_data);
static xqc_int_t xqc_moq_wt_uni_close_notify(
    xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *user_data);


/* ---- vtable ---- */

const xqc_moq_trans_stream_ops_t xqc_moq_wt_stream_ops = {
    .create      = xqc_moq_wt_stream_create,
    .quic_stream = xqc_moq_wt_quic_stream,
    .close       = xqc_moq_wt_stream_close,
    .write       = xqc_moq_wt_stream_send,
};


/* ---- WT stream callbacks ---- */

const xqc_webtransport_stream_callbacks_t xqc_moq_wt_stream_callbacks = {
    .wt_bidistream_create_notify = xqc_moq_wt_bidi_create_notify,
    .wt_bidistream_read_notify   = xqc_moq_wt_bidi_read_notify,
    .wt_bidistream_close_notify  = xqc_moq_wt_bidi_close_notify,
    .wt_unistream_create_notify  = xqc_moq_wt_uni_create_notify,
    .wt_unistream_read_notify    = xqc_moq_wt_uni_read_notify,
    .wt_unistream_close_notify   = xqc_moq_wt_uni_close_notify,
};


/* ---- write retry timer ---- */

static void
xqc_moq_wt_write_retry_timeout(xqc_gp_timer_id_t timer_id,
    xqc_usec_t now, void *user_data)
{
    xqc_moq_wt_stream_wrapper_t *wrapper =
        (xqc_moq_wt_stream_wrapper_t *)user_data;
    if (wrapper == NULL || wrapper->moq_stream == NULL) {
        return;
    }

    xqc_int_t ret = xqc_moq_stream_write(wrapper->moq_stream);
    if (ret < 0) {
        xqc_log(wrapper->moq_stream->session->log, XQC_LOG_ERROR,
                "|wt write retry failed|ret:%d|", ret);
    }
}

static void
xqc_moq_wt_arm_write_retry(xqc_moq_wt_stream_wrapper_t *wrapper)
{
    xqc_moq_session_t *session = wrapper->moq_stream->session;
    xqc_usec_t now = xqc_monotonic_timestamp();

    if (wrapper->retry_timer_id < 0) {
        wrapper->retry_timer_id = xqc_timer_register_gp_timer(
            session->timer_manager, "moq_wt_write_retry",
            xqc_moq_wt_write_retry_timeout, wrapper);
    }

    xqc_timer_gp_timer_set(session->timer_manager,
        wrapper->retry_timer_id,
        now + XQC_MOQ_WT_WRITE_RETRY_INTERVAL);
}


/* ---- vtable implementation ---- */

static void *
xqc_moq_wt_stream_create(void *conn, xqc_stream_direction_t dir,
    void *user_data)
{
    xqc_wt_session_t *wt_session = (xqc_wt_session_t *)conn;
    xqc_moq_stream_t *moq_stream = (xqc_moq_stream_t *)user_data;

    xqc_moq_wt_stream_wrapper_t *wrapper =
        xqc_calloc(1, sizeof(xqc_moq_wt_stream_wrapper_t));
    if (wrapper == NULL) {
        return NULL;
    }
    wrapper->dir = dir;
    wrapper->moq_stream = moq_stream;
    wrapper->retry_timer_id = -1;

    if (dir == XQC_STREAM_BIDI) {
        wrapper->wt.bidi = xqc_wt_session_create_bidi_stream(wt_session);
        if (wrapper->wt.bidi == NULL) {
            xqc_free(wrapper);
            return NULL;
        }

    } else {
        /* uni: use session's CONNECT h3_stream as placeholder (SEND type
         * does not actually use it — verified in xqc_wt_create_unistream) */
        xqc_h3_stream_t *h3s =
            xqc_wt_session_get_h3_stream(wt_session);
        wrapper->wt.uni = xqc_wt_create_unistream(
            XQC_WT_STREAM_TYPE_SEND, wt_session, NULL, h3s);
        if (wrapper->wt.uni == NULL) {
            xqc_free(wrapper);
            return NULL;
        }
    }

    /* set moq_stream as user_data on the underlying QUIC stream,
     * mirroring what xqc_stream_create_with_direction does for QUIC */
    xqc_stream_t *quic_stream = xqc_moq_wt_quic_stream(wrapper);
    if (quic_stream) {
        xqc_stream_set_user_data(quic_stream, moq_stream);
    }

    return wrapper;
}

static xqc_stream_t *
xqc_moq_wt_quic_stream(void *stream)
{
    xqc_moq_wt_stream_wrapper_t *wrapper =
        (xqc_moq_wt_stream_wrapper_t *)stream;
    if (wrapper == NULL) {
        return NULL;
    }

    if (wrapper->dir == XQC_STREAM_BIDI) {
        if (wrapper->wt.bidi && wrapper->wt.bidi->send_stream) {
            return wrapper->wt.bidi->send_stream->stream;
        }
    } else {
        if (wrapper->wt.uni
            && wrapper->wt.uni->type == XQC_WT_STREAM_TYPE_SEND
            && wrapper->wt.uni->stream.send_stream)
        {
            return wrapper->wt.uni->stream.send_stream->stream;
        }
    }

    return NULL;
}

static xqc_int_t
xqc_moq_wt_stream_close(void *stream)
{
    xqc_moq_wt_stream_wrapper_t *wrapper =
        (xqc_moq_wt_stream_wrapper_t *)stream;
    if (wrapper == NULL) {
        return XQC_OK;
    }

    /* unregister retry timer to prevent use-after-free */
    if (wrapper->retry_timer_id >= 0 && wrapper->moq_stream) {
        xqc_timer_unregister_gp_timer(
            wrapper->moq_stream->session->timer_manager,
            wrapper->retry_timer_id);
        wrapper->retry_timer_id = -1;
    }

    /* close underlying QUIC stream first, then free WT wrapper */
    xqc_stream_t *quic_stream = xqc_moq_wt_quic_stream(stream);
    if (quic_stream) {
        xqc_stream_close(quic_stream);
    }

    if (wrapper->dir == XQC_STREAM_BIDI) {
        xqc_wt_bidistream_destroy(wrapper->wt.bidi);
    } else {
        xqc_wt_unistream_destroy(wrapper->wt.uni);
    }

    xqc_free(wrapper);
    return XQC_OK;
}

static ssize_t
xqc_moq_wt_stream_send(void *stream, uint8_t *send_data,
    size_t send_data_size, uint8_t fin)
{
    xqc_moq_wt_stream_wrapper_t *wrapper =
        (xqc_moq_wt_stream_wrapper_t *)stream;
    if (wrapper == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret;
    if (wrapper->dir == XQC_STREAM_BIDI) {
        ret = xqc_wt_bidistream_send(wrapper->wt.bidi,
            send_data, (uint32_t)send_data_size, fin);
    } else {
        ret = xqc_wt_unistream_send(wrapper->wt.uni,
            send_data, (uint32_t)send_data_size, fin);
    }

    /*
     * Normalize WT flow-control block codes to -XQC_EAGAIN.
     * xqc_stream_send() does the same internally for raw QUIC;
     * the caller (xqc_moq_stream_write) only recognizes EAGAIN.
     */
    if (ret == -XQC_ECONN_BLOCKED || ret == -XQC_ESTREAM_BLOCKED) {
        /* arm write-retry timer since WT has no write_notify callback */
        xqc_moq_wt_arm_write_retry(wrapper);
        return -XQC_EAGAIN;
    }

    if (ret == -XQC_EAGAIN) {
        xqc_moq_wt_arm_write_retry(wrapper);
    }

    return ret;
}


/* ---- WT stream lifecycle callbacks ---- */

/*
 * Helper: look up the MOQ session from a WT session's underlying
 * QUIC connection user_data.  Same mechanism as the QUIC adapter's
 * xqc_get_conn_user_data_by_stream.
 */
static xqc_moq_session_t *
xqc_moq_wt_get_session(xqc_wt_session_t *wt_session)
{
    xqc_connection_t *conn = xqc_wt_session_get_conn(wt_session);
    if (conn == NULL) {
        return NULL;
    }
    xqc_moq_user_session_t *user_session =
        (xqc_moq_user_session_t *)conn->user_data;
    if (user_session == NULL || user_session->session == NULL) {
        return NULL;
    }
    return user_session->session;
}

static xqc_int_t
xqc_moq_wt_bidi_create_notify(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_moq_session_t *moq_session = xqc_moq_wt_get_session(session);
    if (moq_session == NULL) {
        return -XQC_ENULLPTR;
    }

    xqc_moq_stream_t *moq_stream = xqc_moq_stream_create(moq_session);
    if (moq_stream == NULL) {
        return -XQC_EMALLOC;
    }

    /* wrap the incoming WT bidi stream */
    xqc_moq_wt_stream_wrapper_t *wrapper =
        xqc_calloc(1, sizeof(xqc_moq_wt_stream_wrapper_t));
    if (wrapper == NULL) {
        xqc_moq_stream_destroy(moq_stream);
        return -XQC_EMALLOC;
    }
    wrapper->dir = XQC_STREAM_BIDI;
    wrapper->wt.bidi = stream;
    wrapper->moq_stream = moq_stream;
    wrapper->retry_timer_id = -1;
    moq_stream->trans_stream = wrapper;

    /* set user_data on the underlying QUIC stream for cross-referencing */
    xqc_stream_t *quic_stream = xqc_moq_wt_quic_stream(wrapper);
    if (quic_stream) {
        xqc_stream_set_user_data(quic_stream, moq_stream);
    }

    /* first client-initiated bidi stream is the control stream */
    if (moq_session->ctl_stream == NULL) {
        moq_session->ctl_stream = moq_stream;
    }

    return XQC_OK;
}

static xqc_int_t
xqc_moq_wt_bidi_read_notify(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t data_len,
    uint8_t fin, void *user_data)
{
    xqc_moq_session_t *moq_session = xqc_moq_wt_get_session(session);
    if (moq_session == NULL) {
        return -XQC_ENULLPTR;
    }

    /* find the moq_stream via underlying QUIC stream user_data */
    xqc_wt_bidistream_t *bidi = stream;
    xqc_stream_t *quic_stream = bidi->send_stream
        ? bidi->send_stream->stream : NULL;
    if (quic_stream == NULL) {
        return -XQC_ENULLPTR;
    }

    xqc_moq_stream_t *moq_stream =
        (xqc_moq_stream_t *)quic_stream->user_data;
    if (moq_stream == NULL) {
        return -XQC_ENULLPTR;
    }

    /* WT pushes data directly — no recv loop needed */
    return xqc_moq_stream_process(moq_stream, data, data_len, fin);
}

static xqc_int_t
xqc_moq_wt_bidi_close_notify(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_wt_bidistream_t *bidi = stream;
    xqc_stream_t *quic_stream = bidi->send_stream
        ? bidi->send_stream->stream : NULL;
    if (quic_stream == NULL) {
        return XQC_OK;
    }

    xqc_moq_stream_t *moq_stream =
        (xqc_moq_stream_t *)quic_stream->user_data;
    if (moq_stream == NULL) {
        return XQC_OK;
    }

    xqc_moq_stream_destroy(moq_stream);
    return XQC_OK;
}

static xqc_int_t
xqc_moq_wt_uni_create_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_moq_session_t *moq_session = xqc_moq_wt_get_session(session);
    if (moq_session == NULL) {
        return -XQC_ENULLPTR;
    }

    xqc_moq_stream_t *moq_stream = xqc_moq_stream_create(moq_session);
    if (moq_stream == NULL) {
        return -XQC_EMALLOC;
    }

    xqc_moq_wt_stream_wrapper_t *wrapper =
        xqc_calloc(1, sizeof(xqc_moq_wt_stream_wrapper_t));
    if (wrapper == NULL) {
        xqc_moq_stream_destroy(moq_stream);
        return -XQC_EMALLOC;
    }
    wrapper->dir = XQC_STREAM_UNI;
    wrapper->wt.uni = stream;
    wrapper->moq_stream = moq_stream;
    wrapper->retry_timer_id = -1;
    moq_stream->trans_stream = wrapper;

    /* for recv-type unistreams, underlying stream is accessed via conn */
    xqc_stream_t *quic_stream = xqc_moq_wt_quic_stream(wrapper);
    if (quic_stream) {
        xqc_stream_set_user_data(quic_stream, moq_stream);
    }

    return XQC_OK;
}

static xqc_int_t
xqc_moq_wt_uni_read_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t data_len,
    uint8_t fin, void *user_data)
{
    xqc_moq_session_t *moq_session = xqc_moq_wt_get_session(session);
    if (moq_session == NULL) {
        return -XQC_ENULLPTR;
    }

    /*
     * For recv-type unistreams the send_stream field is NULL;
     * look up moq_stream via the wrapper stored in create_notify.
     * The user_data parameter from WT callbacks is strm_user_data
     * which we did not set — use conn user_data path instead.
     */
    xqc_stream_t *quic_stream = NULL;
    if (stream->type == XQC_WT_STREAM_TYPE_SEND
        && stream->stream.send_stream)
    {
        quic_stream = stream->stream.send_stream->stream;
    } else if (stream->type == XQC_WT_STREAM_TYPE_RECV
               && stream->stream.recv_stream)
    {
        quic_stream = stream->stream.recv_stream->stream;
    }

    if (quic_stream == NULL) {
        return -XQC_ENULLPTR;
    }

    xqc_moq_stream_t *moq_stream =
        (xqc_moq_stream_t *)quic_stream->user_data;
    if (moq_stream == NULL) {
        return -XQC_ENULLPTR;
    }

    return xqc_moq_stream_process(moq_stream, data, data_len, fin);
}

static xqc_int_t
xqc_moq_wt_uni_close_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_stream_t *quic_stream = NULL;
    if (stream->type == XQC_WT_STREAM_TYPE_SEND
        && stream->stream.send_stream)
    {
        quic_stream = stream->stream.send_stream->stream;
    } else if (stream->type == XQC_WT_STREAM_TYPE_RECV
               && stream->stream.recv_stream)
    {
        quic_stream = stream->stream.recv_stream->stream;
    }

    if (quic_stream == NULL) {
        return XQC_OK;
    }

    xqc_moq_stream_t *moq_stream =
        (xqc_moq_stream_t *)quic_stream->user_data;
    if (moq_stream == NULL) {
        return XQC_OK;
    }

    xqc_moq_stream_destroy(moq_stream);
    return XQC_OK;
}
