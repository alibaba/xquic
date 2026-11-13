/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Fuzz target: the transport parameter decoders.
 *
 * The first byte selects the decoder. With its high bit clear, the rest is
 * the quic_transport_parameters extension of a ClientHello (low bit clear)
 * or of EncryptedExtensions (low bit set); a set that decodes must encode
 * again and decode to the same RFC 9000 values. With the high bit set, the
 * rest is the text of remembered parameters that a client application
 * hands back for 0-RTT, as save_tp_cb gave it: without a terminating NUL.
 */

#include <stdlib.h>
#include <string.h>

#include "src/transport/xqc_transport_params.h"
#include "xqc_fuzz_common.h"

#define XQC_FUZZ_TP_MAX_LEN  65536

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void xqc_fuzz_check_round_trip(const xqc_transport_params_t *params,
                                      xqc_transport_params_type_t exttype);


static void
xqc_fuzz_check_round_trip(const xqc_transport_params_t *params,
                          xqc_transport_params_type_t exttype)
{
    static uint8_t probe[XQC_FUZZ_TP_MAX_LEN];
    xqc_transport_params_t again;
    uint8_t *out;
    size_t lo, hi, mid, cap, out_len = 0;

    /*
     * the encoder refuses a buffer smaller than the length that it computes
     * before it writes anything: find that length, then encode into a heap
     * buffer of exactly that size, so that ASan catches a longer encoding
     */
    if (xqc_encode_transport_params(params, exttype, probe, sizeof(probe),
                                    &out_len)
        != XQC_OK)
    {
        return;
    }
    lo = 0;
    hi = sizeof(probe);
    while (lo < hi) {
        mid = lo + (hi - lo) / 2;
        if (xqc_encode_transport_params(params, exttype, probe, mid, &out_len)
            == XQC_OK)
        {
            hi = mid;

        } else {
            lo = mid + 1;
        }
    }
    cap = lo;

    out = malloc(cap ? cap : 1);
    if (out == NULL) {
        return;
    }

    if (xqc_encode_transport_params(params, exttype, out, cap, &out_len)
        != XQC_OK)
    {
        abort();
    }

    memset(&again, 0, sizeof(again));
    if (out_len > cap
        || xqc_decode_transport_params(&again, exttype, out, out_len) != XQC_OK
        || again.max_idle_timeout != params->max_idle_timeout
        || again.max_udp_payload_size != params->max_udp_payload_size
        || again.initial_max_data != params->initial_max_data
        || again.initial_max_stream_data_bidi_local
               != params->initial_max_stream_data_bidi_local
        || again.initial_max_stream_data_bidi_remote
               != params->initial_max_stream_data_bidi_remote
        || again.initial_max_stream_data_uni
               != params->initial_max_stream_data_uni
        || again.initial_max_streams_bidi != params->initial_max_streams_bidi
        || again.initial_max_streams_uni != params->initial_max_streams_uni
        || again.ack_delay_exponent != params->ack_delay_exponent
        || again.max_ack_delay != params->max_ack_delay
        || again.active_connection_id_limit
               != params->active_connection_id_limit
        || again.max_datagram_frame_size != params->max_datagram_frame_size)
    {
        abort();
    }

    free(out);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xqc_fuzz_input_t in = {data, size};
    xqc_transport_params_t params;
    xqc_transport_params_type_t exttype;
    const uint8_t *body;
    uint8_t mode;
    size_t len;
    char *buf;

    mode = xqc_fuzz_u8(&in);
    len = xqc_fuzz_take(&in, in.size, &body);

    /* a heap copy of the exact size, so that ASan catches overreads */
    buf = malloc(len ? len : 1);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, body, len);

    if (mode & 0x80) {
        /* xqc_connect() reads remembered parameters only when there are */
        if (len > 0) {
            xqc_init_transport_params(&params);
            (void)xqc_read_transport_params(buf, len, &params);
        }

    } else {
        exttype = (mode & 0x01) ? XQC_TP_TYPE_ENCRYPTED_EXTENSIONS
                                : XQC_TP_TYPE_CLIENT_HELLO;
        memset(&params, 0, sizeof(params));
        if (xqc_decode_transport_params(&params, exttype, (uint8_t *)buf, len)
            == XQC_OK)
        {
            xqc_fuzz_check_round_trip(&params, exttype);
        }
    }

    free(buf);
    return 0;
}
