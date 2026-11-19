/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Fuzz target: QPACK (RFC 9204).
 *
 * One QPACK instance plays a local endpoint: its decoder reads the peer's
 * encoder stream and field sections, its encoder reads the peer's decoder
 * stream. The input is a series of operations, each a selector byte and
 * most of them a length-prefixed chunk:
 *
 *   0  encoder stream instructions from the peer
 *   1  part of a field section on one of four request streams; the stream
 *      waits like an HTTP/3 request stream while it is blocked
 *   2  decoder stream instructions from the peer
 *   3  a field section that the local encoder encodes, with names and
 *      values from the chunk, so that the peer's decoder stream has
 *      references to acknowledge
 *   4  the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY, then the local
 *      encoder's table capacity
 */

#include <stdlib.h>
#include <string.h>

#include "src/common/utils/var_buf/xqc_var_buf.h"
#include "src/http3/xqc_h3_header.h"
#include "src/http3/qpack/xqc_qpack.h"
#include "xqc_fuzz_common.h"

#define XQC_FUZZ_QPACK_STREAMS     4
#define XQC_FUZZ_QPACK_CAPACITY    4096
#define XQC_FUZZ_QPACK_MAX_FIELDS  16

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct xqc_fuzz_qpack_stream_s {
    xqc_rep_ctx_t *ctx;
    xqc_http_headers_t headers;
    xqc_bool_t blocked;
} xqc_fuzz_qpack_stream_t;

typedef struct xqc_fuzz_qpack_s {
    xqc_var_buf_t *ins[2];
} xqc_fuzz_qpack_t;


static xqc_var_buf_t *
xqc_fuzz_qpack_get_buf(xqc_qpack_ins_type_t type, void *user_data)
{
    xqc_fuzz_qpack_t *fq = user_data;

    return fq->ins[type == XQC_INS_TYPE_ENCODER ? 0 : 1];
}

/* the instructions are sent at once: empty the buffer */
static ssize_t
xqc_fuzz_qpack_write_ins(xqc_qpack_ins_type_t type, xqc_var_buf_t *buf,
                         void *user_data)
{
    ssize_t sent = (ssize_t)buf->data_len;

    buf->data_len = 0;
    buf->consumed_len = 0;
    return sent;
}

static const xqc_qpack_ins_cb_t xqc_fuzz_qpack_ins_cb = {
    .get_buf_cb = xqc_fuzz_qpack_get_buf,
    .write_ins_cb = xqc_fuzz_qpack_write_ins,
};

/* a field section from the chunk: a length byte, a name, a value, ... */
static void
xqc_fuzz_qpack_encode(xqc_qpack_t *qpk, uint64_t stream_id,
                      const uint8_t *chunk, size_t len)
{
    xqc_http_header_t fields[XQC_FUZZ_QPACK_MAX_FIELDS];
    xqc_http_headers_t headers;
    xqc_fuzz_input_t in = {chunk, len};
    xqc_var_buf_t *rep;
    const uint8_t *p;
    size_t n = 0, l;

    while (in.size > 0 && n < XQC_FUZZ_QPACK_MAX_FIELDS) {
        memset(&fields[n], 0, sizeof(fields[n]));
        fields[n].flags = xqc_fuzz_u8(&in) & 0x03;
        l = xqc_fuzz_take(&in, xqc_fuzz_u8(&in) % 64, &p);
        fields[n].name.iov_base = (void *)p;
        fields[n].name.iov_len = l;
        l = xqc_fuzz_take(&in, xqc_fuzz_u8(&in), &p);
        fields[n].value.iov_base = (void *)p;
        fields[n].value.iov_len = l;
        n++;
    }

    headers.headers = fields;
    headers.count = n;
    headers.capacity = XQC_FUZZ_QPACK_MAX_FIELDS;
    headers.total_len = 0;

    rep = xqc_var_buf_create(4096);
    if (rep == NULL) {
        return;
    }
    (void)xqc_qpack_enc_headers(qpk, stream_id, &headers, rep);
    xqc_var_buf_free(rep);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xqc_fuzz_input_t in = {data, size};
    xqc_fuzz_qpack_t fq;
    xqc_fuzz_qpack_stream_t streams[XQC_FUZZ_QPACK_STREAMS];
    xqc_fuzz_qpack_stream_t *s;
    xqc_qpack_t *qpk;
    const uint8_t *chunk;
    unsigned char *buf;
    xqc_bool_t blocked, fin;
    uint64_t ric;
    ssize_t read;
    size_t len;
    uint8_t op;
    int i;

    memset(&fq, 0, sizeof(fq));
    memset(streams, 0, sizeof(streams));
    fq.ins[0] = xqc_var_buf_create(XQC_FUZZ_QPACK_CAPACITY);
    fq.ins[1] = xqc_var_buf_create(XQC_FUZZ_QPACK_CAPACITY);
    qpk = xqc_qpack_create(XQC_FUZZ_QPACK_CAPACITY, XQC_FUZZ_QPACK_CAPACITY,
                           xqc_fuzz_log(), &xqc_fuzz_qpack_ins_cb, &fq);
    if (fq.ins[0] == NULL || fq.ins[1] == NULL || qpk == NULL) {
        goto end;
    }
    (void)xqc_qpack_set_max_blocked_stream(qpk, 2);

    for (i = 0; i < XQC_FUZZ_QPACK_STREAMS; i++) {
        streams[i].ctx = xqc_qpack_create_req_ctx(i * 4);
        if (streams[i].ctx == NULL
            || xqc_h3_headers_create_buf(&streams[i].headers, 16) != XQC_OK)
        {
            goto end;
        }
    }

    while (in.size > 0) {
        op = xqc_fuzz_u8(&in);

        switch (op % 5) {
        case 0:
        case 2:
            len = xqc_fuzz_chunk(&in, &chunk);
            /* a heap copy of the exact size, so that ASan sees overreads */
            buf = malloc(len ? len : 1);
            if (buf == NULL) {
                goto end;
            }
            memcpy(buf, chunk, len);
            read = op % 5 == 0 ? xqc_qpack_process_encoder(qpk, buf, len)
                               : xqc_qpack_process_decoder(qpk, buf, len);
            free(buf);
            /* a QPACK stream error closes the HTTP/3 connection */
            if (read < 0) {
                goto end;
            }
            break;

        case 1:
            s = &streams[(op >> 3) % XQC_FUZZ_QPACK_STREAMS];
            fin = (op >> 5) & 1;
            len = xqc_fuzz_chunk(&in, &chunk);

            /* a blocked request stream reads again once it can decode */
            if (s->blocked) {
                ric = xqc_qpack_get_req_rqrd_insert_cnt(s->ctx);
                if (xqc_qpack_get_dec_insert_count(qpk) < ric) {
                    break;
                }
                s->blocked = XQC_FALSE;
            }

            buf = malloc(len ? len : 1);
            if (buf == NULL) {
                goto end;
            }
            memcpy(buf, chunk, len);
            blocked = XQC_FALSE;
            read = xqc_qpack_dec_headers(qpk, s->ctx, buf, len, &s->headers,
                                         16384, fin, &blocked);
            free(buf);
            if (read < 0) {
                goto end;
            }

            if (blocked) {
                s->blocked = XQC_TRUE;

            } else if (fin) {
                /* the HEADERS frame is complete */
                xqc_qpack_clear_req_ctx(s->ctx);
                xqc_h3_headers_clear(&s->headers);
            }
            break;

        case 3:
            len = xqc_fuzz_chunk(&in, &chunk);
            xqc_fuzz_qpack_encode(qpk, ((op >> 3) % 8) * 4, chunk, len);
            break;

        default:
            (void)xqc_qpack_set_enc_max_dtable_cap(qpk, xqc_fuzz_u16(&in));
            (void)xqc_qpack_set_dtable_cap(qpk, xqc_fuzz_u16(&in));
            break;
        }
    }

end:
    for (i = 0; i < XQC_FUZZ_QPACK_STREAMS; i++) {
        if (streams[i].ctx != NULL) {
            xqc_qpack_destroy_req_ctx(streams[i].ctx);
        }
        xqc_h3_headers_free(&streams[i].headers);
    }
    if (qpk != NULL) {
        xqc_qpack_destroy(qpk);
    }
    xqc_var_buf_free(fq.ins[0]);
    xqc_var_buf_free(fq.ins[1]);
    return 0;
}
