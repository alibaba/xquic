/*
 * CBMC harnesses for the HTTP/3 frame parser (src/http3/frame/xqc_h3_frame.c)
 * and the QPACK parsers (src/http3/qpack/xqc_prefixed_int.c,
 * xqc_prefixed_str.c with the Huffman decoder, xqc_ins.c, xqc_rep.c).
 *
 * The stream parsers keep state between calls, so the harnesses feed one
 * unconstrained buffer in two chunks split at a nondeterministic point, with
 * the same loop as their callers in src/http3/xqc_h3_stream.c and
 * src/http3/qpack/xqc_qpack.c / xqc_decoder.c.  Every parser call checks the
 * contract of those loops: a result in [0, chunk length].
 */
#include "common.h"

#include "src/http3/frame/xqc_h3_frame.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_defs.h"
#include "src/http3/qpack/xqc_prefixed_int.h"
#include "src/http3/qpack/xqc_prefixed_str.h"
#include "src/http3/qpack/xqc_ins.h"
#include "src/http3/qpack/xqc_rep.h"
#include "src/common/utils/var_buf/xqc_var_buf.h"
#include "src/common/utils/huffman/xqc_huffman.h"

/* ---- HTTP/3 frames ------------------------------------------------------- */

/*
 * One chunk through the loop of xqc_h3_stream_process_control() and
 * xqc_h3_stream_process_push(): parse until the chunk is used up, reset the
 * context at the end of every frame, fail on any error.
 */
static int
h3_feed(xqc_h3_frame_pctx_t *pctx, const unsigned char *data, size_t len)
{
    size_t processed = 0;
    while (processed < len) {
        ssize_t read = xqc_h3_frm_parse(data + processed, len - processed, pctx,
                                        NULL);
        if (read < 0) {
            return -1;
        }
        __CPROVER_assert((size_t)read <= len - processed,
                         "h3 frame: read <= available");
        processed += read;
        if (pctx->state != XQC_H3_FRM_STATE_END && processed != len) {
            return -1;
        }
        if (pctx->state == XQC_H3_FRM_STATE_END) {
            xqc_h3_frm_reset_pctx(pctx);
        }
    }
    return 0;
}

void
harness_h3_frm_parse(void)
{
    size_t len;
    unsigned char *buf = cbmc_buf(0, &len);
    size_t split = nondet_size_t();
    __CPROVER_assume(split <= len);

    xqc_h3_frame_pctx_t pctx;
    memset(&pctx, 0, sizeof(pctx));
    pctx.state = XQC_H3_FRM_STATE_TYPE;
    pctx.frame.type = XQC_H3_FRM_UNKNOWN;

    if (h3_feed(&pctx, buf, split) == 0) {
        (void)h3_feed(&pctx, buf + split, len - split);
    }
    /* what xqc_h3_stream_destroy() does with an unfinished frame */
    xqc_h3_frm_reset_pctx(&pctx);
    free(buf);
}

/*
 * xqc_h3_frm_parse_setting() runs on the payload of a complete SETTINGS
 * frame.  The connection is a stub with the fields that the function and
 * XQC_H3_CONN_ERR() read.
 */
static xqc_h3_settings_result_t
stub_extern_settings_notify(xqc_h3_conn_t *h3c, const xqc_h3_setting_t *entries,
                            size_t count, void *user_data)
{
    /* the application reads every entry it is given */
    for (size_t i = 0; i < count; i++) {
        volatile uint64_t id = entries[i].identifier;
        volatile uint64_t v = entries[i].value;
        (void)id;
        (void)v;
    }
    xqc_h3_settings_result_t r;
    return r;
}

void
harness_h3_frm_parse_setting(void)
{
    size_t len;
    unsigned char *data = cbmc_buf(0, &len);
    xqc_var_buf_t vb;
    vb.data = data;
    vb.buf_len = len;
    vb.data_len = len;
    vb.consumed_len = 0;

    xqc_connection_t *conn = malloc(sizeof(*conn));
    __CPROVER_assume(conn != NULL);
    conn->conn_err = 0;
    xqc_h3_conn_t *h3c = malloc(sizeof(*h3c));
    __CPROVER_assume(h3c != NULL);
    h3c->conn = conn;
    if (nondet_int()) {
        h3c->h3_conn_callbacks.h3_conn_peer_extern_settings_notify
            = stub_extern_settings_notify;
    } else {
        h3c->h3_conn_callbacks.h3_conn_peer_extern_settings_notify = NULL;
    }

    (void)xqc_h3_frm_parse_setting(&vb, h3c);

    free(h3c);
    free(conn);
    free(data);
}

/* ---- QPACK: prefixed integers and strings -------------------------------- */

void
harness_prefixed_int_read(void)
{
    size_t len;
    unsigned char *buf = cbmc_buf(1, &len);
    size_t split = nondet_size_t();
    __CPROVER_assume(split >= 1 && split <= len);
    size_t prefix = nondet_size_t();
    __CPROVER_assume(prefix >= 1 && prefix <= 8);

    xqc_prefixed_int_t pint;
    xqc_prefixed_int_init(&pint, prefix);
    int fin = 0;
    ssize_t r = xqc_prefixed_int_read(&pint, buf, buf + split, &fin);
    __CPROVER_assert(r < 0 || (size_t)r <= split,
                     "prefixed int: read <= available");
    if (r >= 0 && !fin && split < len) {
        __CPROVER_assert((size_t)r == split,
                         "prefixed int: unfinished read uses all input");
        r = xqc_prefixed_int_read(&pint, buf + split, buf + len, &fin);
        __CPROVER_assert(r < 0 || (size_t)r <= len - split,
                         "prefixed int: read <= available");
    }
    if (r >= 0 && fin) {
        __CPROVER_assert(pint.value <= XQC_QPACK_INT_MAX,
                         "prefixed int: value <= 2^62 - 1");
    }
    free(buf);
}

void
harness_prefixed_str(void)
{
    size_t len;
    unsigned char *buf = cbmc_buf(1, &len);
    size_t split = nondet_size_t();
    __CPROVER_assume(split >= 1 && split <= len);
    uint8_t n = nondet_uchar();
    __CPROVER_assume(
        n >= 3 && n <= 7); /* the prefixes that xqc_ins.c and xqc_rep.c use */

    /* as xqc_rep_ctx_create() */
    xqc_prefixed_str_t *ps = xqc_prefixed_str_pctx_create(
        XQC_VAR_BUF_INIT_SIZE, XQC_H3_MAX_FIELD_SECTION_SIZE);
    __CPROVER_assume(ps != NULL);
    xqc_prefixed_str_init(ps, n);

    int fin = 0;
    ssize_t r = xqc_parse_prefixed_str(ps, buf, split, &fin);
    __CPROVER_assert(r < 0 || (size_t)r <= split,
                     "prefixed str: read <= available");
    if (r >= 0 && !fin && split < len) {
        r = xqc_parse_prefixed_str(ps, buf + split, len - split, &fin);
        __CPROVER_assert(r < 0 || (size_t)r <= len - split,
                         "prefixed str: read <= available");
    }
    if (r >= 0 && fin) {
        __CPROVER_assert(ps->value->data_len < ps->value->buf_len
                             && ps->value->data[ps->value->data_len] == '\0',
                         "prefixed str: NUL-terminated within the buffer");
        __CPROVER_assert(ps->value->data_len <= XQC_H3_MAX_FIELD_SECTION_SIZE,
                         "prefixed str: length <= max_str_len");
    }
    xqc_prefixed_str_free(ps);
    free(buf);
}

/* ---- QPACK: encoder and decoder stream instructions ---------------------- */

/* the loop of xqc_qpack_process_encoder(), without the table updates */
static int
enc_feed(xqc_ins_enc_ctx_t *ctx, unsigned char *data, size_t len)
{
    size_t processed = 0;
    while (processed < len) {
        ssize_t read = xqc_ins_parse_encoder(data + processed, len - processed,
                                             ctx);
        if (read < 0) {
            return -1;
        }
        __CPROVER_assert((size_t)read <= len - processed,
                         "encoder ins: read <= available");
        processed += read;
        if (ctx->state != XQC_INS_ES_STATE_FINISH && len != processed) {
            return -1;
        }
    }
    return 0;
}

void
harness_ins_parse_encoder(void)
{
    size_t len;
    unsigned char *buf = cbmc_buf(0, &len);
    size_t split = nondet_size_t();
    __CPROVER_assume(split <= len);

    xqc_ins_enc_ctx_t *ctx = xqc_ins_encoder_ctx_create();
    __CPROVER_assume(ctx != NULL);
    if (enc_feed(ctx, buf, split) == 0) {
        (void)enc_feed(ctx, buf + split, len - split);
    }
    xqc_ins_encoder_ctx_free(ctx);
    free(buf);
}

/* the loop of xqc_qpack_process_decoder() */
static int
dec_feed(xqc_ins_dec_ctx_t *ctx, unsigned char *data, size_t len)
{
    size_t processed = 0;
    while (processed < len) {
        ssize_t read = xqc_ins_parse_decoder(data + processed, len - processed,
                                             ctx);
        if (read < 0) {
            return -1;
        }
        __CPROVER_assert((size_t)read <= len - processed,
                         "decoder ins: read <= available");
        processed += read;
        if (ctx->state != XQC_INS_DS_STATE_FINISH && len != processed) {
            return -1;
        }
    }
    return 0;
}

void
harness_ins_parse_decoder(void)
{
    size_t len;
    unsigned char *buf = cbmc_buf(0, &len);
    size_t split = nondet_size_t();
    __CPROVER_assume(split <= len);

    xqc_ins_dec_ctx_t *ctx = xqc_ins_decoder_ctx_create();
    __CPROVER_assume(ctx != NULL);
    if (dec_feed(ctx, buf, split) == 0) {
        (void)dec_feed(ctx, buf + split, len - split);
    }
    xqc_ins_decoder_ctx_free(ctx);
    free(buf);
}

/* ---- QPACK: field section prefix and field line representations ---------- */

/*
 * The loop of xqc_qpack_dec_headers() / xqc_decoder_dec_header() without the
 * table lookups: the encoded field section prefix, then field lines, each
 * reset after it finishes.  max_ents and the insert count are those of a
 * decoder whose table allows up to 4096 bytes (max_ents = 4096 / 32).
 */
static int
rep_feed(xqc_rep_ctx_t *ctx, size_t max_ents, uint64_t icnt,
         unsigned char *data, size_t len)
{
    size_t processed = 0;
    while (processed < len) {
        ssize_t read;
        if (ctx->state < XQC_REP_DECODE_STATE_OPCODE) {
            read = xqc_rep_decode_prefix(ctx, max_ents, icnt, data + processed,
                                         len - processed);
            if (read < 0) {
                return -1;
            }
            __CPROVER_assert((size_t)read <= len - processed,
                             "prefix: read <= available");
            processed += read;
        }
        if (ctx->state > XQC_REP_DECODE_STATE_RICNT && ctx->ric.value > icnt) {
            return -1; /* blocked */
        }
        if (ctx->state >= XQC_REP_DECODE_STATE_OPCODE) {
            read = xqc_rep_decode_field_line(ctx, data + processed,
                                             len - processed);
            if (read < 0) {
                return -1;
            }
            __CPROVER_assert((size_t)read <= len - processed,
                             "field line: read <= available");
            processed += read;
            if (ctx->state == XQC_REP_DECODE_STATE_FINISH) {
                xqc_rep_ctx_clear_rep(ctx);
            } else if (processed != len) {
                return -1;
            }
        }
    }
    return 0;
}

void
harness_rep_decode(void)
{
    size_t len;
    unsigned char *buf = cbmc_buf(0, &len);
    size_t split = nondet_size_t();
    __CPROVER_assume(split <= len);
    size_t max_ents = nondet_size_t();
    __CPROVER_assume(max_ents <= 4096 / 32);
    uint64_t icnt = nondet_u64();
    __CPROVER_assume(icnt <= 1000000);

    xqc_rep_ctx_t *ctx = xqc_rep_ctx_create(0);
    __CPROVER_assume(ctx != NULL);
    if (rep_feed(ctx, max_ents, icnt, buf, split) == 0) {
        (void)rep_feed(ctx, max_ents, icnt, buf + split, len - split);
    }
    xqc_rep_ctx_free(ctx);
    free(buf);
}

/* ---- QPACK: the Huffman decoder on its own ------------------------------- */

/*
 * xqc_huffman_dec() as xqc_parse_prefixed_str() calls it: a destination of
 * at least one byte (the caller prepares 2 * l bytes, l >= 1), any decoder
 * state left by an earlier call, any input of up to MAXLEN bytes.
 */
void
harness_huffman_dec(void)
{
    size_t srclen;
    unsigned char *src = cbmc_buf(0, &srclen);
    size_t dstlen = nondet_size_t();
    __CPROVER_assume(dstlen >= 1 && dstlen <= 2 * MAXLEN);
    unsigned char *dst = malloc(dstlen);
    __CPROVER_assume(dst != NULL);

    xqc_huffman_dec_ctx ctx;
    ctx.state = nondet_uchar();
    ctx.pre_state = nondet_uchar();
    ctx.bit = nondet_uchar();
    ctx.end = nondet_int() ? XQC_TRUE : XQC_FALSE;
    ctx.high_bits = nondet_int() ? XQC_TRUE : XQC_FALSE;

    size_t write = 0;
    int fin = nondet_int();
    ssize_t r = xqc_huffman_dec(&ctx, dst, dstlen, src, srclen, fin, &write);
    if (r >= 0) {
        __CPROVER_assert((size_t)r <= srclen, "huffman: read <= input length");
        __CPROVER_assert(write <= dstlen,
                         "huffman: write <= destination length");
    }
    free(dst);
    free(src);
}

/*
 * One xqc_h3_frm_parse() call on one chunk, with any frame state that an
 * earlier call can leave (type and length parsed or not).  The two-chunk
 * stream harness above does not fit in memory even for 5 bytes.
 */
void
harness_h3_frm_parse_once(void)
{
    size_t len;
    unsigned char *buf = cbmc_buf(1, &len);

    xqc_h3_frame_pctx_t pctx;
    memset(&pctx, 0, sizeof(pctx));
    pctx.state = XQC_H3_FRM_STATE_TYPE;
    pctx.frame.type = XQC_H3_FRM_UNKNOWN;

    ssize_t read = xqc_h3_frm_parse(buf, len, &pctx, NULL);
    __CPROVER_assert(read < 0 || (size_t)read <= len,
                     "h3 frame: read <= available");
    xqc_h3_frm_reset_pctx(&pctx);
    free(buf);
}
