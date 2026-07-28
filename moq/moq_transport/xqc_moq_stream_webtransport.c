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
#include "src/http3/xqc_h3_stream.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "xquic/xqc_webtransport.h"

/* retry interval for write-blocked streams (microseconds) */
#define XQC_MOQ_WT_WRITE_RETRY_INTERVAL     (50 * 1000)


/*
 * Wrapper around WT stream objects.  Holds the WT handle, stream direction
 * flag, a retry timer for write-blocked conditions (WT has no
 * stream_write_notify callback like raw QUIC does), and a list node linking
 * it into the session's WT stream registry.
 */
typedef struct xqc_moq_wt_stream_wrapper_s {
    xqc_stream_direction_t  dir;
    xqc_wt_session_t       *wt_session;
    union {
        xqc_wt_bidistream_t *bidi;
        xqc_wt_unistream_t  *uni;
    } wt;
    xqc_moq_stream_t       *moq_stream;   /* back-pointer for timer cb */
    xqc_gp_timer_id_t       retry_timer_id;
    xqc_list_head_t         list_member;   /* session->wt_stream_list */
} xqc_moq_wt_stream_wrapper_t;


/*
 * WT stream -> moq_stream mapping.
 *
 * The xquic WebTransport API exposes no per-stream application user_data
 * (unlike the raw QUIC stream API's xqc_stream_set_user_data).  WT bidi
 * streams and incoming RECV uni streams also carry a per-stream
 * xqc_h3_stream_t that owns the underlying QUIC stream's user_data slot, so
 * that slot cannot be reused.  Following Tengine's ngx_http_webtransport
 * module (the reference xquic-WT consumer), MOQ keeps a session-scoped
 * registry of WT stream wrappers and looks up the moq_stream by scanning it.
 */
static xqc_moq_wt_stream_wrapper_t *
xqc_moq_wt_find_wrapper_by_bidi(xqc_moq_session_t *session,
    xqc_wt_bidistream_t *bidi)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_wt_stream_wrapper_t *wrapper;
    xqc_list_for_each_safe(pos, next, &session->wt_stream_list) {
        wrapper = xqc_list_entry(pos, xqc_moq_wt_stream_wrapper_t, list_member);
        if (wrapper->dir == XQC_STREAM_BIDI && wrapper->wt.bidi == bidi) {
            return wrapper;
        }
    }
    return NULL;
}

static xqc_moq_wt_stream_wrapper_t *
xqc_moq_wt_find_wrapper_by_uni(xqc_moq_session_t *session,
    xqc_wt_unistream_t *uni)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_wt_stream_wrapper_t *wrapper;
    xqc_list_for_each_safe(pos, next, &session->wt_stream_list) {
        wrapper = xqc_list_entry(pos, xqc_moq_wt_stream_wrapper_t, list_member);
        if (wrapper->dir == XQC_STREAM_UNI && wrapper->wt.uni == uni) {
            return wrapper;
        }
    }
    return NULL;
}

static xqc_moq_stream_t *
xqc_moq_wt_find_moq_by_bidi(xqc_moq_session_t *session,
    xqc_wt_bidistream_t *bidi)
{
    xqc_moq_wt_stream_wrapper_t *wrapper =
        xqc_moq_wt_find_wrapper_by_bidi(session, bidi);
    return wrapper ? wrapper->moq_stream : NULL;
}

static xqc_moq_stream_t *
xqc_moq_wt_find_moq_by_uni(xqc_moq_session_t *session,
    xqc_wt_unistream_t *uni)
{
    xqc_moq_wt_stream_wrapper_t *wrapper =
        xqc_moq_wt_find_wrapper_by_uni(session, uni);
    return wrapper ? wrapper->moq_stream : NULL;
}

/* link a wrapper into the session's WT stream registry */
static void
xqc_moq_wt_link_wrapper(xqc_moq_session_t *session,
    xqc_moq_wt_stream_wrapper_t *wrapper)
{
    xqc_init_list_head(&wrapper->list_member);
    xqc_list_add_tail(&wrapper->list_member, &session->wt_stream_list);
}


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
static xqc_int_t xqc_moq_wt_uni_closing_notify(
    xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *user_data);
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
    .wt_unistream_closing_notify = xqc_moq_wt_uni_closing_notify,
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
    if (session->timer_manager == NULL) {
        return;
    }
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

static void
xqc_moq_wt_disarm_write_retry(xqc_moq_wt_stream_wrapper_t *wrapper)
{
    xqc_moq_session_t *session = wrapper->moq_stream->session;
    if (wrapper->retry_timer_id >= 0 && session->timer_manager) {
        /*
         * This may run from the retry timer's own callback. Unregistering
         * would free the timer while the timer manager still references it
         * after the callback returns; just unset it here and unregister it
         * when the stream wrapper is destroyed.
         */
        xqc_timer_gp_timer_unset(session->timer_manager,
            wrapper->retry_timer_id);
    }
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
    wrapper->wt_session = wt_session;
    wrapper->moq_stream = moq_stream;
    wrapper->retry_timer_id = -1;

    if (dir == XQC_STREAM_BIDI) {
        wrapper->wt.bidi = xqc_wt_session_create_bidi_stream(wt_session);
        if (wrapper->wt.bidi == NULL) {
            xqc_free(wrapper);
            return NULL;
        }

    } else {
        xqc_h3_stream_t *h3s =
            xqc_wt_session_get_h3_stream(wt_session);
        xqc_int_t create_err = -XQC_ECREATE_STREAM;
        wrapper->wt.uni = xqc_wt_create_unistream_with_error(
            XQC_WT_STREAM_TYPE_SEND, wt_session, NULL, h3s, &create_err);
        if (wrapper->wt.uni == NULL
            && create_err != -XQC_ESTREAM_BLOCKED)
        {
            xqc_free(wrapper);
            return NULL;
        }
    }

    /* register the wrapper so WT read/close callbacks can recover the
     * moq_stream from the WT handle (see xqc_moq_wt_find_moq_by_*) */
    xqc_moq_wt_link_wrapper(moq_stream->session, wrapper);

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
        if (wrapper->wt.uni) {
            if (wrapper->wt.uni->type == XQC_WT_STREAM_TYPE_SEND
                && wrapper->wt.uni->stream.send_stream)
            {
                return wrapper->wt.uni->stream.send_stream->stream;
            }
            if (wrapper->wt.uni->type == XQC_WT_STREAM_TYPE_RECV
                && wrapper->wt.uni->stream.recv_stream)
            {
                return wrapper->wt.uni->stream.recv_stream->stream;
            }
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

    /* unregister retry timer; MOQ won't retry after explicit close */
    if (wrapper->retry_timer_id >= 0 && wrapper->moq_stream) {
        xqc_timer_unregister_gp_timer(
            wrapper->moq_stream->session->timer_manager,
            wrapper->retry_timer_id);
        wrapper->retry_timer_id = -1;
    }

    /*
     * Only trigger close of the underlying QUIC stream here — the wrapper
     * and moq_stream are torn down later in wt_*_close_notify, which the WT
     * module fires when the stream is fully closed. This mirrors the
     * raw-QUIC path: xqc_moq_stream_close() only calls xqc_stream_close(),
     * and the moq_stream is freed in stream_close_notify. The WT bidi/uni
     * struct itself is freed by the WT module after wt_*_close_notify
     * returns (xqc_wt_bidistream_destroy in wt_bs_close_notify).
     */
    xqc_stream_t *quic_stream = xqc_moq_wt_quic_stream(stream);
    if (quic_stream) {
        xqc_stream_close(quic_stream);
        return XQC_OK;
    }

    /*
     * A credit-blocked uni stream has no WT/QUIC handle and therefore will
     * never receive a transport close callback. Complete its teardown here.
     */
    xqc_moq_stream_t *moq_stream = wrapper->moq_stream;
    xqc_list_del_init(&wrapper->list_member);
    if (moq_stream) {
        xqc_moq_stream_destroy(moq_stream);
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
    if (wrapper->dir == XQC_STREAM_UNI && wrapper->wt.uni == NULL) {
        xqc_h3_stream_t *h3s =
            xqc_wt_session_get_h3_stream(wrapper->wt_session);
        wrapper->wt.uni = xqc_wt_create_unistream_with_error(
            XQC_WT_STREAM_TYPE_SEND, wrapper->wt_session, NULL, h3s, &ret);
        if (wrapper->wt.uni == NULL) {
            if (ret == -XQC_ESTREAM_BLOCKED) {
                xqc_moq_wt_arm_write_retry(wrapper);
                return -XQC_EAGAIN;
            }
            return ret;
        }
        if (wrapper->moq_stream->enable_fec) {
            xqc_init_quic_fec(wrapper->moq_stream);
        }
        if (wrapper->moq_stream->priority != XQC_STREAM_PRI_DEFAULT) {
            xqc_stream_t *quic_stream =
                xqc_moq_wt_quic_stream(wrapper);
            if (quic_stream) {
                xqc_stream_set_priority(quic_stream,
                    wrapper->moq_stream->priority);
            }
        }
    }

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
        return ret;
    }

    if (ret >= 0) {
        xqc_bool_t fin_complete = XQC_TRUE;
        if (fin) {
            fin_complete = wrapper->dir == XQC_STREAM_BIDI
                ? wrapper->wt.bidi->send_fin
                : wrapper->wt.uni->fin.send_fin;
        }
        if ((size_t)ret < send_data_size || !fin_complete) {
            xqc_moq_wt_arm_write_retry(wrapper);
        } else {
            xqc_moq_wt_disarm_write_retry(wrapper);
        }
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

    /*
     * Active WT bidi streams are notified again when their receive side
     * first becomes readable. They are already registered by create(), so
     * this is an idempotent notification, not a second control stream.
     */
    if (xqc_moq_wt_find_wrapper_by_bidi(moq_session, stream) != NULL) {
        return XQC_OK;
    }

    xqc_h3_stream_t *h3_stream =
        xqc_wt_bidistream_get_h3_stream(stream);
    xqc_stream_t *quic_stream = h3_stream ? h3_stream->stream : NULL;
    xqc_bool_t is_client_bidi =
        quic_stream
        && xqc_get_stream_type(quic_stream->stream_id) == XQC_CLI_BID;
    if (is_client_bidi && moq_session->ctl_stream != NULL) {
        xqc_log(moq_session->log, XQC_LOG_ERROR,
            "|duplicate control stream|stream_id:%ui|",
            quic_stream->stream_id);
        return -XQC_EPROTO;
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

    /* register the wrapper in the session's WT stream registry */
    xqc_moq_wt_link_wrapper(moq_session, wrapper);

    /* the first client-initiated bidi stream is the control stream */
    if (is_client_bidi) {
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

    /* recover moq_stream from the session's WT stream registry */
    xqc_moq_stream_t *moq_stream =
        xqc_moq_wt_find_moq_by_bidi(moq_session, stream);
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
    xqc_moq_session_t *moq_session = xqc_moq_wt_get_session(session);
    if (moq_session == NULL) {
        return XQC_OK;
    }

    xqc_moq_wt_stream_wrapper_t *wrapper =
        xqc_moq_wt_find_wrapper_by_bidi(moq_session, stream);
    if (wrapper == NULL) {
        return XQC_OK;
    }

    /* unregister retry timer before tearing down */
    if (wrapper->retry_timer_id >= 0) {
        xqc_timer_unregister_gp_timer(moq_session->timer_manager,
            wrapper->retry_timer_id);
        wrapper->retry_timer_id = -1;
    }

    xqc_moq_stream_t *moq_stream = wrapper->moq_stream;
    /*
     * xqc_moq_stream_destroy reads trans_stream (this wrapper) to recover
     * the underlying quic_stream; the WT bidi is still valid here because
     * the WT module frees it only AFTER this callback returns.
     */
    xqc_moq_stream_destroy(moq_stream);

    /* unlink our wrapper and free it; the WT bidi itself is freed by the
     * WT module after this callback (xqc_wt_bidistream_destroy). */
    xqc_list_del_init(&wrapper->list_member);
    xqc_free(wrapper);
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

    /* register the wrapper in the session's WT stream registry */
    xqc_moq_wt_link_wrapper(moq_session, wrapper);

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

    /* recover moq_stream from the session's WT stream registry */
    xqc_moq_stream_t *moq_stream =
        xqc_moq_wt_find_moq_by_uni(moq_session, stream);
    if (moq_stream == NULL) {
        return -XQC_ENULLPTR;
    }

    return xqc_moq_stream_process(moq_stream, data, data_len, fin);
}

static xqc_int_t
xqc_moq_wt_uni_closing_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    /*
     * RESET_STREAM is an early notification. Keep the MoQ stream context
     * until WT delivers the final close callback, matching the raw QUIC path.
     */
    return XQC_OK;
}

static xqc_int_t
xqc_moq_wt_uni_close_notify(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_moq_session_t *moq_session = xqc_moq_wt_get_session(session);
    if (moq_session == NULL) {
        return XQC_OK;
    }

    xqc_moq_wt_stream_wrapper_t *wrapper =
        xqc_moq_wt_find_wrapper_by_uni(moq_session, stream);
    if (wrapper == NULL) {
        return XQC_OK;
    }

    /* unregister retry timer before tearing down */
    if (wrapper->retry_timer_id >= 0) {
        xqc_timer_unregister_gp_timer(moq_session->timer_manager,
            wrapper->retry_timer_id);
        wrapper->retry_timer_id = -1;
    }

    xqc_moq_stream_t *moq_stream = wrapper->moq_stream;
    /* xqc_moq_stream_destroy reads trans_stream (this wrapper); the WT uni
     * is still valid here — the WT module frees it only AFTER this callback
     * returns (xqc_wt_unistream_destroy in wt_bs_close_notify). */
    xqc_moq_stream_destroy(moq_stream);

    /* unlink our wrapper and free it; the WT uni itself is freed by the
     * WT module after this callback. */
    xqc_list_del_init(&wrapper->list_member);
    xqc_free(wrapper);
    return XQC_OK;
}


/*
 * Clean up any WT stream wrappers still on the session's registry.
 *
 * Per-stream closing callbacks normally remove wrappers. Session teardown
 * still needs a safety-net sweep because the WT session can be unregistered
 * before every underlying stream reaches its individual callback.
 *
 * The demos destroy the MoQ session from webtransport_session_close_notify,
 * before the WT layer releases its stream handles. NULL the handles anyway:
 * xqc_moq_stream_destroy only needs them for optional transport statistics,
 * and teardown must not retain or dereference a closing WT stream.
 */
void
xqc_moq_wt_cleanup_stream_list(xqc_moq_session_t *session)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_wt_stream_wrapper_t *wrapper;

    xqc_list_for_each_safe(pos, next, &session->wt_stream_list) {
        wrapper = xqc_list_entry(pos, xqc_moq_wt_stream_wrapper_t,
            list_member);

        if (wrapper->retry_timer_id >= 0) {
            xqc_timer_unregister_gp_timer(session->timer_manager,
                wrapper->retry_timer_id);
            wrapper->retry_timer_id = -1;
        }

        /* NULL out WT handle — may already be freed by
         * xqc_wt_session_close; prevents UAF in quic_stream() */
        if (wrapper->dir == XQC_STREAM_BIDI) {
            wrapper->wt.bidi = NULL;
        } else {
            wrapper->wt.uni = NULL;
        }

        if (wrapper->moq_stream) {
            xqc_moq_stream_destroy(wrapper->moq_stream);
        }

        xqc_list_del_init(&wrapper->list_member);
        xqc_free(wrapper);
    }
}
