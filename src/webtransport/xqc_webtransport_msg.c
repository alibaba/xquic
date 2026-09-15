/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <limits.h>
#include <string.h>

#include <xquic/xqc_webtransport_msg.h>

#include "src/common/xqc_malloc.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

#define XQC_WT_MSG_FIXED_HEADER_SIZE 2
#define XQC_WT_MSG_MIN_HEADER_SIZE 3
#define XQC_WT_MSG_MAX_HEADER_SIZE 10
#define XQC_WT_MSG_WIRE_LENGTH_MAX ((1ULL << 62) - 1)

struct xqc_wt_msg_stream_s {
    xqc_wt_bidistream_t       *stream;
    xqc_wt_msg_recv_notify_pt  recv_notify;
    void                      *user_data;
    size_t                     max_message_size;
    size_t                     call_depth;
    xqc_bool_t                 destroy_pending;

    unsigned char             *send_buf;
    size_t                     send_len;
    size_t                     send_offset;
    xqc_int_t                  send_error;
    xqc_bool_t                 send_fin_pending;
    xqc_bool_t                 send_fin;
    xqc_bool_t                 in_send;

    unsigned char              recv_header[XQC_WT_MSG_MAX_HEADER_SIZE];
    size_t                     recv_header_len;
    size_t                     recv_header_need;
    unsigned char             *recv_buf;
    size_t                     recv_len;
    size_t                     recv_offset;
    xqc_wt_msg_type_t          recv_type;
    xqc_int_t                  recv_error;
    xqc_bool_t                 recv_fin;
    xqc_bool_t                 in_recv;
};

static void xqc_wt_msg_send_clear(xqc_wt_msg_stream_t *msg_stream);
static void xqc_wt_msg_recv_reset(xqc_wt_msg_stream_t *msg_stream);
static void xqc_wt_msg_stream_free(xqc_wt_msg_stream_t *msg_stream);
static void xqc_wt_msg_stream_retain(xqc_wt_msg_stream_t *msg_stream);
static xqc_int_t xqc_wt_msg_stream_release(
    xqc_wt_msg_stream_t *msg_stream, xqc_int_t ret);
static xqc_int_t xqc_wt_msg_recv_fail(xqc_wt_msg_stream_t *msg_stream,
    xqc_int_t error);
static xqc_int_t xqc_wt_msg_send_fail(xqc_wt_msg_stream_t *msg_stream,
    xqc_int_t error);
static xqc_int_t xqc_wt_msg_stream_do_flush(
    xqc_wt_msg_stream_t *msg_stream);
static xqc_int_t xqc_wt_msg_recv_header(xqc_wt_msg_stream_t *msg_stream);
static xqc_bool_t xqc_wt_msg_recv_deliver(
    xqc_wt_msg_stream_t *msg_stream);

static void
xqc_wt_msg_send_clear(xqc_wt_msg_stream_t *msg_stream)
{
    xqc_free(msg_stream->send_buf);
    msg_stream->send_buf = NULL;
    msg_stream->send_len = 0;
    msg_stream->send_offset = 0;
}

static void
xqc_wt_msg_recv_reset(xqc_wt_msg_stream_t *msg_stream)
{
    msg_stream->recv_header_len = 0;
    msg_stream->recv_header_need = XQC_WT_MSG_MIN_HEADER_SIZE;
    msg_stream->recv_buf = NULL;
    msg_stream->recv_len = 0;
    msg_stream->recv_offset = 0;
    msg_stream->recv_type = XQC_WT_MSG_BINARY;
}

static void
xqc_wt_msg_stream_free(xqc_wt_msg_stream_t *msg_stream)
{
    xqc_wt_msg_send_clear(msg_stream);
    xqc_free(msg_stream->recv_buf);
    xqc_free(msg_stream);
}

static void
xqc_wt_msg_stream_retain(xqc_wt_msg_stream_t *msg_stream)
{
    msg_stream->call_depth++;
}

static xqc_int_t
xqc_wt_msg_stream_release(xqc_wt_msg_stream_t *msg_stream, xqc_int_t ret)
{
    msg_stream->call_depth--;
    if (msg_stream->call_depth == 0 && msg_stream->destroy_pending) {
        xqc_wt_msg_stream_free(msg_stream);
    }
    return ret;
}

static xqc_int_t
xqc_wt_msg_recv_fail(xqc_wt_msg_stream_t *msg_stream, xqc_int_t error)
{
    xqc_free(msg_stream->recv_buf);
    xqc_wt_msg_recv_reset(msg_stream);
    msg_stream->recv_error = error;
    return error;
}

xqc_wt_msg_stream_t *
xqc_wt_msg_stream_create(xqc_wt_bidistream_t *stream,
    size_t max_message_size, xqc_wt_msg_recv_notify_pt recv_notify,
    void *user_data, int *err)
{
    if (err != NULL) {
        *err = XQC_OK;
    }
    if (stream == NULL || max_message_size == 0 || recv_notify == NULL
        || (uint64_t)max_message_size > XQC_WT_MSG_WIRE_LENGTH_MAX)
    {
        if (err != NULL) {
            *err = -XQC_EPARAM;
        }
        return NULL;
    }

    xqc_wt_msg_stream_t *msg_stream = xqc_calloc(1, sizeof(*msg_stream));
    if (msg_stream == NULL) {
        if (err != NULL) {
            *err = -XQC_EMALLOC;
        }
        return NULL;
    }

    msg_stream->stream = stream;
    msg_stream->max_message_size = max_message_size;
    msg_stream->recv_notify = recv_notify;
    msg_stream->user_data = user_data;
    xqc_wt_msg_recv_reset(msg_stream);
    return msg_stream;
}

void
xqc_wt_msg_stream_destroy(xqc_wt_msg_stream_t *msg_stream)
{
    if (msg_stream == NULL) {
        return;
    }
    if (msg_stream->call_depth != 0) {
        msg_stream->destroy_pending = XQC_TRUE;
        return;
    }
    xqc_wt_msg_stream_free(msg_stream);
}

static xqc_int_t
xqc_wt_msg_send_fail(xqc_wt_msg_stream_t *msg_stream, xqc_int_t error)
{
    xqc_wt_msg_send_clear(msg_stream);
    msg_stream->send_fin_pending = XQC_FALSE;
    msg_stream->send_error = error;
    return error;
}

static xqc_int_t
xqc_wt_msg_stream_do_flush(xqc_wt_msg_stream_t *msg_stream)
{
    while (msg_stream->send_buf != NULL) {
        size_t remaining = msg_stream->send_len - msg_stream->send_offset;
        if (remaining == 0) {
            xqc_wt_msg_send_clear(msg_stream);
            break;
        }

        uint32_t chunk = remaining > INT32_MAX
            ? INT32_MAX : (uint32_t)remaining;
        xqc_int_t sent = xqc_wt_bidistream_send(msg_stream->stream,
            msg_stream->send_buf + msg_stream->send_offset, chunk, 0);
        if (msg_stream->destroy_pending) {
            return XQC_OK;
        }
        if (sent == -XQC_EAGAIN || sent == 0) {
            return XQC_OK;
        }
        if (sent < 0) {
            return xqc_wt_msg_send_fail(msg_stream, sent);
        }
        if ((uint32_t)sent > chunk) {
            return xqc_wt_msg_send_fail(msg_stream, -XQC_EPROTO);
        }

        msg_stream->send_offset += (size_t)sent;
        if ((uint32_t)sent < chunk) {
            return XQC_OK;
        }
    }

    if (msg_stream->send_fin_pending) {
        xqc_int_t sent = xqc_wt_bidistream_send(msg_stream->stream,
                                                NULL, 0, 1);
        if (msg_stream->destroy_pending) {
            return XQC_OK;
        }
        if (sent == -XQC_EAGAIN) {
            return XQC_OK;
        }
        if (sent < 0) {
            return xqc_wt_msg_send_fail(msg_stream, sent);
        }
        if (sent != 0) {
            return xqc_wt_msg_send_fail(msg_stream, -XQC_EPROTO);
        }
        msg_stream->send_fin_pending = XQC_FALSE;
        msg_stream->send_fin = XQC_TRUE;
    }

    return XQC_OK;
}

xqc_int_t
xqc_wt_msg_stream_flush(xqc_wt_msg_stream_t *msg_stream)
{
    if (msg_stream == NULL) {
        return -XQC_EPARAM;
    }
    xqc_wt_msg_stream_retain(msg_stream);
    if (msg_stream->destroy_pending) {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ESTATE);
    }
    if (msg_stream->send_error != XQC_OK) {
        return xqc_wt_msg_stream_release(msg_stream,
                                         msg_stream->send_error);
    }
    if (msg_stream->in_send) {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ESTATE);
    }

    msg_stream->in_send = XQC_TRUE;
    xqc_int_t ret = xqc_wt_msg_stream_do_flush(msg_stream);
    msg_stream->in_send = XQC_FALSE;
    return xqc_wt_msg_stream_release(msg_stream, ret);
}

xqc_int_t
xqc_wt_msg_stream_send_msg(xqc_wt_msg_stream_t *msg_stream,
    xqc_wt_msg_type_t type, const void *data, size_t data_len)
{
    if (msg_stream == NULL || (data == NULL && data_len != 0)
        || (type != XQC_WT_MSG_BINARY && type != XQC_WT_MSG_TEXT))
    {
        return -XQC_EPARAM;
    }
    xqc_wt_msg_stream_retain(msg_stream);
    if (msg_stream->destroy_pending) {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ESTATE);
    }
    if (msg_stream->send_error != XQC_OK) {
        return xqc_wt_msg_stream_release(msg_stream,
                                         msg_stream->send_error);
    }
    if (msg_stream->send_fin_pending || msg_stream->send_fin) {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ESTATE);
    }
    if (msg_stream->send_buf != NULL) {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_EAGAIN);
    }
    if (data_len > msg_stream->max_message_size
        || (uint64_t)data_len > XQC_WT_MSG_WIRE_LENGTH_MAX)
    {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ELIMIT);
    }

    size_t length_len = xqc_put_varint_len((uint64_t)data_len);
    size_t header_len = XQC_WT_MSG_FIXED_HEADER_SIZE + length_len;
    if (data_len > SIZE_MAX - header_len) {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ELIMIT);
    }

    msg_stream->send_len = header_len + data_len;
    msg_stream->send_buf = xqc_malloc(msg_stream->send_len);
    if (msg_stream->send_buf == NULL) {
        msg_stream->send_len = 0;
        return xqc_wt_msg_stream_release(msg_stream, -XQC_EMALLOC);
    }

    msg_stream->send_buf[0] = XQC_WT_MSG_VERSION_0;
    msg_stream->send_buf[1] = type == XQC_WT_MSG_TEXT
        ? XQC_WT_MSG_FLAG_TEXT : 0;
    /* RFC 9000 Section 16 defines this QUIC variable-length integer. */
    if (xqc_put_varint(msg_stream->send_buf
                       + XQC_WT_MSG_FIXED_HEADER_SIZE,
                       (uint64_t)data_len) == NULL)
    {
        xqc_wt_msg_send_clear(msg_stream);
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ELIMIT);
    }
    if (data_len != 0) {
        memcpy(msg_stream->send_buf + header_len, data, data_len);
    }

    xqc_int_t ret = xqc_wt_msg_stream_flush(msg_stream);
    return xqc_wt_msg_stream_release(msg_stream, ret);
}

xqc_int_t
xqc_wt_msg_stream_finish(xqc_wt_msg_stream_t *msg_stream)
{
    if (msg_stream == NULL) {
        return -XQC_EPARAM;
    }
    xqc_wt_msg_stream_retain(msg_stream);
    if (msg_stream->destroy_pending) {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ESTATE);
    }
    if (msg_stream->send_error != XQC_OK) {
        return xqc_wt_msg_stream_release(msg_stream,
                                         msg_stream->send_error);
    }
    if (msg_stream->in_send) {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ESTATE);
    }
    if (msg_stream->send_fin) {
        return xqc_wt_msg_stream_release(msg_stream, XQC_OK);
    }

    msg_stream->send_fin_pending = XQC_TRUE;
    xqc_int_t ret = xqc_wt_msg_stream_flush(msg_stream);
    return xqc_wt_msg_stream_release(msg_stream, ret);
}

static xqc_int_t
xqc_wt_msg_recv_header(xqc_wt_msg_stream_t *msg_stream)
{
    if (msg_stream->recv_header[0] != XQC_WT_MSG_VERSION_0) {
        return -XQC_EVERSION;
    }

    const unsigned char *length = msg_stream->recv_header
        + XQC_WT_MSG_FIXED_HEADER_SIZE;
    size_t length_len = xqc_get_varint_len(length);
    if (msg_stream->recv_header_need
        != XQC_WT_MSG_FIXED_HEADER_SIZE + length_len)
    {
        msg_stream->recv_header_need = XQC_WT_MSG_FIXED_HEADER_SIZE
            + length_len;
        return XQC_OK;
    }

    uint64_t payload_len = 0;
    if (xqc_vint_read(length, length + length_len, &payload_len)
        != (int)length_len)
    {
        return -XQC_EPROTO;
    }
    if (payload_len > msg_stream->max_message_size
        || payload_len > SIZE_MAX)
    {
        return -XQC_ELIMIT;
    }

    msg_stream->recv_type = msg_stream->recv_header[1]
        & XQC_WT_MSG_FLAG_TEXT ? XQC_WT_MSG_TEXT : XQC_WT_MSG_BINARY;
    msg_stream->recv_len = (size_t)payload_len;
    if (msg_stream->recv_len != 0) {
        msg_stream->recv_buf = xqc_malloc(msg_stream->recv_len);
        if (msg_stream->recv_buf == NULL) {
            return -XQC_EMALLOC;
        }
    }
    return XQC_OK;
}

static xqc_bool_t
xqc_wt_msg_recv_deliver(xqc_wt_msg_stream_t *msg_stream)
{
    unsigned char *payload = msg_stream->recv_buf;
    size_t payload_len = msg_stream->recv_len;
    xqc_wt_msg_type_t type = msg_stream->recv_type;

    xqc_wt_msg_recv_reset(msg_stream);
    msg_stream->recv_notify(msg_stream, type, payload, payload_len,
                            msg_stream->user_data);
    xqc_free(payload);
    return !msg_stream->destroy_pending;
}

xqc_int_t
xqc_wt_msg_stream_recv_msg(xqc_wt_msg_stream_t *msg_stream,
    const void *data, size_t data_len)
{
    if (msg_stream == NULL || (data == NULL && data_len != 0)) {
        return -XQC_EPARAM;
    }
    xqc_wt_msg_stream_retain(msg_stream);
    if (msg_stream->destroy_pending) {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ESTATE);
    }
    if (msg_stream->recv_error != XQC_OK) {
        return xqc_wt_msg_stream_release(msg_stream,
                                         msg_stream->recv_error);
    }
    if (msg_stream->recv_fin || msg_stream->in_recv) {
        return xqc_wt_msg_stream_release(msg_stream, -XQC_ESTATE);
    }

    unsigned char empty;
    const unsigned char *pos = data_len == 0 ? &empty : data;
    const unsigned char *end = pos + data_len;
    msg_stream->in_recv = XQC_TRUE;

    while (pos < end) {
        if (msg_stream->recv_header_len < msg_stream->recv_header_need) {
            size_t needed = msg_stream->recv_header_need
                - msg_stream->recv_header_len;
            size_t available = (size_t)(end - pos);
            size_t copied = needed < available ? needed : available;
            memcpy(msg_stream->recv_header + msg_stream->recv_header_len,
                   pos, copied);
            msg_stream->recv_header_len += copied;
            pos += copied;

            if (msg_stream->recv_header[0] != XQC_WT_MSG_VERSION_0) {
                msg_stream->in_recv = XQC_FALSE;
                xqc_int_t ret = xqc_wt_msg_recv_fail(msg_stream,
                                                     -XQC_EVERSION);
                return xqc_wt_msg_stream_release(msg_stream, ret);
            }
            if (msg_stream->recv_header_len < msg_stream->recv_header_need) {
                break;
            }

            xqc_int_t ret = xqc_wt_msg_recv_header(msg_stream);
            if (ret != XQC_OK) {
                msg_stream->in_recv = XQC_FALSE;
                ret = xqc_wt_msg_recv_fail(msg_stream, ret);
                return xqc_wt_msg_stream_release(msg_stream, ret);
            }
            if (msg_stream->recv_header_len
                < msg_stream->recv_header_need)
            {
                continue;
            }
            if (msg_stream->recv_len == 0) {
                if (!xqc_wt_msg_recv_deliver(msg_stream)) {
                    msg_stream->in_recv = XQC_FALSE;
                    return xqc_wt_msg_stream_release(msg_stream, XQC_OK);
                }
                continue;
            }
        }

        size_t needed = msg_stream->recv_len - msg_stream->recv_offset;
        size_t available = (size_t)(end - pos);
        size_t copied = needed < available ? needed : available;
        memcpy(msg_stream->recv_buf + msg_stream->recv_offset, pos, copied);
        msg_stream->recv_offset += copied;
        pos += copied;

        if (msg_stream->recv_offset == msg_stream->recv_len) {
            if (!xqc_wt_msg_recv_deliver(msg_stream)) {
                msg_stream->in_recv = XQC_FALSE;
                return xqc_wt_msg_stream_release(msg_stream, XQC_OK);
            }
        }
    }

    msg_stream->in_recv = XQC_FALSE;
    if (xqc_wt_bidistream_get_recv_fin(msg_stream->stream)) {
        if (msg_stream->recv_header_len != 0 || msg_stream->recv_buf != NULL) {
            xqc_int_t ret = xqc_wt_msg_recv_fail(msg_stream, -XQC_EPROTO);
            return xqc_wt_msg_stream_release(msg_stream, ret);
        }
        msg_stream->recv_fin = XQC_TRUE;
    }
    return xqc_wt_msg_stream_release(msg_stream, XQC_OK);
}
