/*
 * CBMC harnesses for the transport parameter decoder
 * (src/transport/xqc_transport_params.c), which reads the peer's
 * quic_transport_parameters TLS extension: the ClientHello's on a server,
 * the EncryptedExtensions' on a client.
 *
 * The decoder is checked in two parts, because one harness over the whole
 * loop inlines every value decoder (through the function pointer table) in
 * every iteration and does not fit in memory even for 6 bytes:
 *
 *   harness_tp_loop      the loop of xqc_decode_transport_params() and
 *                        xqc_decode_one_transport_param(), with every
 *                        decoder replaced by a stub that checks the range
 *                        it is given: within the extension and exactly the
 *                        Transport Parameter Length;
 *   harness_tp_decoders  each value decoder of the table on any range of
 *                        0..MAXLEN bytes, which covers every range the loop
 *                        can pass.
 *
 * The file includes the decoder's source so that the static decoders and
 * the decoder index enum are visible.
 */
#include "common.h"

#include "src/transport/xqc_transport_params.c"

xqc_transport_params_type_t nondet_exttype(void);

/* ---- the parameter loop -------------------------------------------------- */

static const uint8_t *g_ext;
static size_t g_ext_len;

static xqc_int_t
stub_decoder(xqc_transport_params_t *params,
             xqc_transport_params_type_t exttype, const uint8_t *p,
             const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    (void)params;
    (void)exttype;
    (void)param_type;
    __CPROVER_assert(p >= g_ext && p <= end && end <= g_ext + g_ext_len,
                     "TP loop: a decoder gets a range within the extension");
    __CPROVER_assert((uint64_t)(end - p) == param_len,
                     "TP loop: the range is the Transport Parameter Length");
    if (p < end) {
        /* a decoder may read any byte of its range */
        volatile uint8_t first = p[0], last = end[-1];
        (void)first;
        (void)last;
    }
    return nondet_int() ? XQC_OK : -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
}

void
harness_tp_loop(void)
{
    size_t len;
    uint8_t *in = cbmc_buf(0, &len);
    g_ext = in;
    g_ext_len = len;

    for (size_t i = 0; i < XQC_TP_DECODER_UNKNOWN; i++) {
        xqc_trans_param_decode_func_list[i] = stub_decoder;
    }

    xqc_transport_params_t *params = malloc(sizeof(*params));
    __CPROVER_assume(params != NULL);
    xqc_transport_params_type_t exttype = nondet_exttype();
    __CPROVER_assume(exttype == XQC_TP_TYPE_CLIENT_HELLO
                     || exttype == XQC_TP_TYPE_ENCRYPTED_EXTENSIONS);

    (void)xqc_decode_transport_params(params, exttype, in, len);

    free(params);
    free(in);
}

/* ---- every value decoder ------------------------------------------------- */

void
harness_tp_decoders(void)
{
    size_t len;
    uint8_t *val = cbmc_buf(0, &len);

    xqc_transport_params_t *params = malloc(sizeof(*params));
    __CPROVER_assume(params != NULL);
    xqc_transport_params_type_t exttype = nondet_exttype();
    __CPROVER_assume(exttype == XQC_TP_TYPE_CLIENT_HELLO
                     || exttype == XQC_TP_TYPE_ENCRYPTED_EXTENSIONS);

    /*
     * The defaults that xqc_decode_transport_params() sets before its loop,
     * for the fields asserted below.  (Calling it with an empty buffer makes
     * cbmc unwind its loop with every decoder inlined.)
     */
    params->ack_delay_exponent = XQC_DEFAULT_ACK_DELAY_EXPONENT;
    params->receive_timestamps_exponent = 0;
    params->max_receive_timestamps_per_ack = 0;
    params->original_dest_connection_id.cid_len = 0;
    params->initial_source_connection_id.cid_len = 0;
    params->retry_source_connection_id.cid_len = 0;
    params->preferred_address_present = 0;
    params->fec_encoder_schemes_num = 0;
    params->fec_decoder_schemes_num = 0;
    params->reset_stream_at = XQC_FALSE;
    xqc_int_t ret;

    /* one parameter id and the decoder that the table gives it */
    uint64_t param_type = nondet_u64();
    __CPROVER_assume(param_type <= XQC_VINT_MAX);
    uint64_t idx = xqc_trans_param_get_index(param_type);
    __CPROVER_assume(idx != XQC_TP_DECODER_UNKNOWN);

    ret = xqc_trans_param_decode_func_list[idx](params, exttype, val, val + len,
                                                param_type, len);
    if (ret == XQC_OK) {
        /* read by the ACK, ACK_MP and ACK_EXTENDED parsers as shift counts */
        __CPROVER_assert(params->ack_delay_exponent <= 20,
                         "TP: ack_delay_exponent <= 20");
        __CPROVER_assert(params->receive_timestamps_exponent <= 20,
                         "TP: receive_timestamps_exponent <= 20");
        __CPROVER_assert(params->max_receive_timestamps_per_ack <= 63,
                         "TP: max_receive_timestamps_per_ack <= 63");
        __CPROVER_assert(params->original_dest_connection_id.cid_len
                                 <= XQC_MAX_CID_LEN
                             && params->initial_source_connection_id.cid_len
                                    <= XQC_MAX_CID_LEN
                             && params->retry_source_connection_id.cid_len
                                    <= XQC_MAX_CID_LEN,
                         "TP: connection ID lengths <= 20");
        if (params->preferred_address_present) {
            __CPROVER_assert(params->preferred_address.cid.cid_len >= 1
                                 && params->preferred_address.cid.cid_len
                                        <= XQC_MAX_CID_LEN,
                             "TP: preferred_address CID length in 1..20");
        }
#ifdef XQC_ENABLE_FEC
        __CPROVER_assert(params->fec_encoder_schemes_num
                                 <= XQC_FEC_MAX_SCHEME_NUM
                             && params->fec_decoder_schemes_num
                                    <= XQC_FEC_MAX_SCHEME_NUM,
                         "TP: FEC scheme counts <= XQC_FEC_MAX_SCHEME_NUM");
#endif
    }
    free(params);
    free(val);
}

#ifdef XQC_ENABLE_FEC
/* the two FEC scheme list decoders, called directly */
void
harness_tp_fec_schemes(void)
{
    size_t len;
    uint8_t *val = cbmc_buf(0, &len);
    xqc_transport_params_t *params = malloc(sizeof(*params));
    __CPROVER_assume(params != NULL);
    params->fec_encoder_schemes_num = 0;
    params->fec_decoder_schemes_num = 0;

    xqc_int_t ret;
    if (nondet_int()) {
        ret = xqc_decode_encoder_schemes(
            params, XQC_TP_TYPE_CLIENT_HELLO, val, val + len,
            XQC_TRANSPORT_PARAM_FEC_ENCODER_SCHEMES, len);
    } else {
        ret = xqc_decode_decoder_schemes(
            params, XQC_TP_TYPE_CLIENT_HELLO, val, val + len,
            XQC_TRANSPORT_PARAM_FEC_DECODER_SCHEMES, len);
    }
    if (ret == XQC_OK) {
        __CPROVER_assert(params->fec_encoder_schemes_num
                                 <= XQC_FEC_MAX_SCHEME_NUM
                             && params->fec_decoder_schemes_num
                                    <= XQC_FEC_MAX_SCHEME_NUM,
                         "TP: FEC scheme counts <= XQC_FEC_MAX_SCHEME_NUM");
    }
    free(params);
    free(val);
}
#endif
