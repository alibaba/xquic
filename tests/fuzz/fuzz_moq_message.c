/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Fuzz target: the MoQ Transport message decoders and the catalog decoder.
 *
 * With bit 0 of the first byte clear, the rest of the input is the byte
 * stream of a MoQ stream, given in chunks of a length from the input. It
 * is decoded like xqc_moq_stream_process() does, without the session
 * handlers that act on complete messages; bit 1 ends the stream with the
 * last chunk. With bit 0 set, the rest is a catalog object for
 * xqc_moq_catalog_decode().
 */

#include <stdlib.h>
#include <string.h>

#include "moq/moq_media/xqc_moq_catalog.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "xqc_fuzz_common.h"

/* xqc_moq_stream_process() keeps at most this many undecoded bytes */
#define XQC_FUZZ_MOQ_REMAIN_MAX  8

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct xqc_fuzz_moq_stream_s {
    xqc_moq_decode_msg_ctx_t ctx;
    uint8_t remain[XQC_FUZZ_MOQ_REMAIN_MAX];
    size_t remain_len;
} xqc_fuzz_moq_stream_t;


static void
xqc_fuzz_moq_clean(xqc_fuzz_moq_stream_t *s)
{
    xqc_moq_msg_free(s->ctx.cur_msg_type, s->ctx.cur_decode_msg);
    s->ctx.cur_decode_msg = NULL;
    xqc_moq_decode_msg_ctx_reset(&s->ctx);
}

/* the decode loop of xqc_moq_stream_process() */
static xqc_int_t
xqc_fuzz_moq_process(xqc_fuzz_moq_stream_t *s, const uint8_t *data, size_t len,
                     uint8_t fin)
{
    xqc_moq_msg_base_t *msg_base;
    xqc_moq_msg_type_t msg_type, cur_type, next_type;
    xqc_moq_decode_state_t next_state;
    xqc_int_t ret, msg_finish, wait_more_data;
    uint8_t *buf;
    size_t buf_len, processed = 0;

    buf_len = s->remain_len + len;
    buf = malloc(buf_len ? buf_len : 1);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }
    memcpy(buf, s->remain, s->remain_len);
    memcpy(buf + s->remain_len, data, len);
    s->remain_len = 0;

    for (;;) {
        msg_finish = 0;
        wait_more_data = 0;

        if (s->ctx.cur_decode_state == XQC_MOQ_DECODE_MSG_TYPE) {
            ret = xqc_moq_msg_decode_type(buf + processed, buf_len - processed,
                                          &msg_type, &wait_more_data);
            if (ret < 0) {
                goto error;
            }
            processed += ret;
            if (wait_more_data) {
                break;
            }
            s->ctx.cur_msg_type = msg_type;
            s->ctx.cur_decode_state = XQC_MOQ_DECODE_MSG;
            continue;
        }

        if (s->ctx.cur_decode_state != XQC_MOQ_DECODE_MSG) {
            ret = -XQC_EILLEGAL_FRAME;
            goto error;
        }

        msg_base = s->ctx.cur_decode_msg;
        if (msg_base == NULL) {
            msg_base = xqc_moq_msg_create(s->ctx.cur_msg_type);
            if (msg_base == NULL) {
                ret = -XQC_EILLEGAL_FRAME;
                goto error;
            }
            s->ctx.cur_decode_msg = msg_base;
        }

        ret = msg_base->decode(buf + processed, buf_len - processed, fin,
                               &s->ctx, msg_base, &msg_finish, &wait_more_data);
        if (ret < 0 || (ret == 0 && !wait_more_data && !msg_finish)) {
            ret = -XQC_EILLEGAL_FRAME;
            goto error;
        }
        if ((size_t)ret > buf_len - processed) {
            abort();
        }
        processed += ret;

        if (wait_more_data) {
            break;
        }

        if (msg_finish) {
            cur_type = s->ctx.cur_msg_type;
            next_state = XQC_MOQ_DECODE_MSG_TYPE;
            next_type = 0xff;
            if (cur_type == XQC_MOQ_MSG_STREAM_HEADER_TRACK
                || cur_type == XQC_MOQ_MSG_TRACK_STREAM_OBJECT)
            {
                next_state = XQC_MOQ_DECODE_MSG;
                next_type = XQC_MOQ_MSG_TRACK_STREAM_OBJECT;

            } else if (cur_type == XQC_MOQ_MSG_STREAM_HEADER_GROUP
                       || cur_type == XQC_MOQ_MSG_GROUP_STREAM_OBJECT)
            {
                next_state = XQC_MOQ_DECODE_MSG;
                next_type = XQC_MOQ_MSG_GROUP_STREAM_OBJECT;
            }
            xqc_fuzz_moq_clean(s);
            s->ctx.cur_decode_state = next_state;
            s->ctx.cur_msg_type = next_type;
        }
    }

    if (buf_len - processed >= XQC_FUZZ_MOQ_REMAIN_MAX) {
        ret = -XQC_EILLEGAL_FRAME;
        goto error;
    }
    s->remain_len = buf_len - processed;
    memcpy(s->remain, buf + processed, s->remain_len);
    free(buf);
    return XQC_OK;

error:
    xqc_fuzz_moq_clean(s);
    free(buf);
    return ret;
}

static void
xqc_fuzz_moq_catalog(const uint8_t *data, size_t len)
{
    xqc_moq_catalog_t catalog;
    uint8_t *buf;

    /* a heap copy of the exact size, so that ASan catches overreads */
    buf = malloc(len ? len : 1);
    if (buf == NULL) {
        return;
    }
    memcpy(buf, data, len);

    xqc_moq_catalog_init(&catalog);
    (void)xqc_moq_catalog_decode(&catalog, buf, len);
    xqc_moq_catalog_free_fields(&catalog);
    free(buf);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xqc_fuzz_input_t in = {data, size};
    xqc_fuzz_moq_stream_t s;
    const uint8_t *chunk;
    uint8_t mode;
    size_t len;

    mode = xqc_fuzz_u8(&in);
    if (mode & 0x01) {
        len = xqc_fuzz_take(&in, in.size, &chunk);
        xqc_fuzz_moq_catalog(chunk, len);
        return 0;
    }

    memset(&s, 0, sizeof(s));
    xqc_moq_decode_msg_ctx_reset(&s.ctx);
    while (in.size > 0) {
        len = xqc_fuzz_take(&in, xqc_fuzz_u8(&in) + 1, &chunk);
        if (xqc_fuzz_moq_process(&s, chunk, len, (mode & 0x02) && in.size == 0)
            != XQC_OK)
        {
            return 0;
        }
    }

    xqc_fuzz_moq_clean(&s);
    return 0;
}
