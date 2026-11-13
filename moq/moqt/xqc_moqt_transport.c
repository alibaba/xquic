/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "xqc_moqt_session.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_packet_out.h"
#ifdef XQC_ENABLE_WEBTRANSPORT
#include "src/webtransport/xqc_webtransport_stream.h"
#endif

xqc_moqt_stream_t *
xqc_moqt_transport_open(xqc_moqt_session_t *s,
    xqc_stream_direction_t direction)
{
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (s->webtransport) {
        int error;
        xqc_wt_stream_base_t *wt = direction == XQC_STREAM_BIDI
            ? (void *)xqc_wt_session_create_bidi_stream(s->wt_session,
                                                         NULL, &error)
            : (void *)xqc_wt_session_create_uni_stream(s->wt_session,
                                                        NULL, &error);
        return wt ? wt->user_data : NULL;
    }
#endif
    xqc_stream_t *raw = xqc_stream_create_with_direction(s->conn, direction,
                                                          NULL);
    return raw ? raw->user_data : NULL;
}

ssize_t
xqc_moqt_transport_send(xqc_moqt_stream_t *st, const void *data,
    size_t len, uint8_t fin)
{
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (st->session->webtransport) {
        xqc_wt_stream_base_t *wt = st->wt_stream;
        size_t amount = xqc_min(len, UINT32_MAX);
        if (!wt) {
            return -XQC_ESTATE;
        }
        return wt->bidi
            ? xqc_wt_bidistream_send((void *)wt, data, amount,
                                       fin && amount == len)
            : xqc_wt_unistream_send((void *)wt, data, amount,
                                      fin && amount == len);
    }
#endif
    return xqc_stream_send(st->transport_stream, (void *)data, len, fin);
}

uint64_t
xqc_moqt_transport_offset(xqc_moqt_stream_t *st)
{
    uint64_t offset = st->transport_stream->stream_send_offset;
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (st->wt_stream) {
        size_t prefix = st->wt_stream->prefix_len;
        return offset > prefix ? offset - prefix : 0;
    }
#endif
    return offset;
}

void
xqc_moqt_transport_reset(xqc_moqt_stream_t *st, uint64_t error)
{
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (st->session->webtransport
        && (st->session->closed || !st->wt_stream || st->wt_stream->closed
            || st->wt_stream->session->closed))
    {
        return;
    }
#endif
    xqc_stream_t *raw = st->transport_stream;
    size_t prefix = st->kind == XQC_MOQT_STREAM_SUBGROUP
        || st->kind == XQC_MOQT_STREAM_FETCH
            ? st->state.data.prefix_length : 0;
    if (prefix && xqc_moqt_transport_offset(st) >= prefix) {
#ifdef XQC_ENABLE_WEBTRANSPORT
        if (st->wt_stream) {
            prefix += st->wt_stream->prefix_len;
        }
#endif
        /* Draft-22 11.3.2: preserve the identifying payload on reset. */
        xqc_stream_set_reliable_size(raw, prefix);
    }
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (st->session->webtransport) {
        xqc_wt_stream_base_t *wt = st->wt_stream;
        uint32_t code = error <= UINT32_MAX ? error
                                           : XQC_MOQT_RESET_INTERNAL_ERROR;
        xqc_bool_t bidi = wt->bidi, receive = wt->can_recv;
        if (wt->can_send && !wt->send_fin && !wt->send_reset) {
            if (bidi) {
                xqc_wt_bidistream_reset((void *)wt, code);
            } else {
                xqc_wt_unistream_reset((void *)wt, code);
            }
        }
        wt = st->wt_stream;
        if (wt && receive && !wt->recv_fin && !wt->recv_reset) {
            if (bidi) {
                xqc_wt_bidistream_stop_sending((void *)wt, code);
            } else {
                xqc_wt_unistream_stop_sending((void *)wt, code);
            }
        }
        return;
    }
#endif
    xqc_stream_close_with_error(raw, error);
}

size_t
xqc_moqt_transport_mss(xqc_moqt_session_t *s)
{
    size_t mss = xqc_datagram_get_mss(s->conn);
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (s->webtransport) {
        if (!s->wt_session) {
            return 0;
        }
        unsigned char bytes[XQC_WT_VARINT_MAX_LEN];
        size_t prefix = xqc_wt_put_varint(s->wt_session->session_id / 4,
                                           bytes, sizeof(bytes));
        mss = xqc_min(mss, XQC_MAX_PACKET_OUT_SIZE);
        return mss > prefix ? mss - prefix : 0;
    }
#endif
    return mss;
}

xqc_int_t
xqc_moqt_transport_datagram(xqc_moqt_session_t *s, const void *data, size_t len)
{
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (s->webtransport) {
        return xqc_wt_session_datagram_send(s->wt_session, data, len, NULL);
    }
#endif
    return xqc_datagram_send(s->conn, (void *)data, len, NULL,
                               XQC_DATA_QOS_NORMAL);
}
