/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "src/http3/frame/xqc_h3_frame.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_ext_bytestream.h"

#include "xqc_common_test.h"


ssize_t
xqc_test_h3_ext_frame_parse(const char *p, size_t sz, xqc_h3_frame_pctx_t *state)
{
    ssize_t offset = 0;
    while (offset < sz) {
        ssize_t len = rand() % sz + 1;
        ssize_t ret = xqc_h3_frm_parse(p + offset, len, state, NULL);
        if (ret < 0) {
            return ret;
        }
        if (ret == 0) {
            return offset;
        }
        offset += ret;
        if (state->state == XQC_H3_FRM_STATE_END) {
            return offset;
        }
    }
    return XQC_ERROR;
}

void
xqc_test_h3_ext_frame()
{
    uint64_t push_id = 10;
    xqc_h3_ext_frame_bidi_stream_type_t stream_type;

    xqc_list_head_t send_buf;
    xqc_init_list_head(&send_buf);

    xqc_h3_frame_pctx_t pctx;
    memset(&pctx, 0, sizeof(xqc_h3_frame_pctx_t));
    ssize_t processed;

    /* write */
    /* write bidi_stream_type frame */
    xqc_int_t ret = xqc_h3_ext_frm_write_bidi_stream_type(&send_buf, XQC_H3_BIDI_STREAM_TYPE_REQUEST, XQC_TRUE);
    CU_ASSERT(ret == XQC_OK);
    /* write bidi_stream_type frame */
    ret = xqc_h3_ext_frm_write_bidi_stream_type(&send_buf, XQC_H3_BIDI_STREAM_TYPE_BYTESTREAM, XQC_TRUE);
    CU_ASSERT(ret == XQC_OK);

    xqc_var_buf_t *buf = xqc_var_buf_create(XQC_VAR_BUF_INIT_SIZE);
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &send_buf) {
        xqc_list_buf_t *list_buf = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_var_buf_t *data_buf = list_buf->buf;
        xqc_var_buf_save_data(buf, data_buf->data, data_buf->data_len);

        xqc_list_del(&list_buf->list_head);
        xqc_var_buf_free(data_buf);
        xqc_free(list_buf);
    }

    /* parse */
    /* parse bidi_stream_type frame */
    processed = xqc_test_h3_ext_frame_parse(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, &pctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_END);
    CU_ASSERT(pctx.frame.frame_payload.stream_type.stream_type.vi == XQC_H3_BIDI_STREAM_TYPE_REQUEST);
    buf->consumed_len += processed;
    xqc_h3_frm_reset_pctx(&pctx);
    /* parse bidi_stream_type frame */
    processed = xqc_test_h3_ext_frame_parse(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, &pctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_END);
    CU_ASSERT(pctx.frame.frame_payload.stream_type.stream_type.vi == XQC_H3_BIDI_STREAM_TYPE_BYTESTREAM);
    buf->consumed_len += processed;
    xqc_h3_frm_reset_pctx(&pctx);

    xqc_var_buf_free(buf);
}


static int    xqc_test_bs_read_cnt;
static size_t xqc_test_bs_read_len;
static int    xqc_test_bs_read_ret;

static int
xqc_test_h3_ext_bytestream_read(xqc_h3_ext_bytestream_t *h3_ext_bs,
    const void *data, size_t data_len, uint8_t fin, void *bs_user_data,
    uint64_t data_recv_time)
{
    xqc_test_bs_read_cnt++;
    xqc_test_bs_read_len += data_len;
    return xqc_test_bs_read_ret;
}

/* queue a received message of the given segments, all of it received */
static void
xqc_test_h3_ext_bytestream_queue_msg(xqc_h3_ext_bytestream_t *bs,
    const char **segs, size_t seg_cnt)
{
    xqc_h3_frame_pctx_t pctx;
    xqc_h3_ext_bytestream_data_buf_t *buf;
    size_t i, len = 0;

    for (i = 0; i < seg_cnt; i++) {
        len += strlen(segs[i]);
    }

    memset(&pctx, 0, sizeof(pctx));
    pctx.frame.len = len;
    buf = xqc_h3_ext_bytestream_get_last_data_buf(bs, &pctx);
    CU_ASSERT_FATAL(buf != NULL);

    for (i = 0; i < seg_cnt; i++) {
        CU_ASSERT(xqc_h3_ext_bytestream_save_data_to_buf(buf,
            (const uint8_t *)segs[i], strlen(segs[i])) == XQC_OK);
    }
    buf->end_time = xqc_monotonic_timestamp();
}

/*
 * xqc_h3_ext_bytestream_notify_read() hands each received message to the
 * application, then frees it: a message of one segment, which is handed
 * over in its own buffer, and one of two segments, merged into a new
 * buffer, with the read callback succeeding, then failing. The test leaks
 * the messages under LeakSanitizer if they are not freed.
 */
void
xqc_test_h3_ext_bytestream_read_frees_message(void)
{
    const char *one[] = {"hello"};
    const char *two[] = {"wor", "ld!"};
    int fail;

    for (fail = 0; fail <= 1; fail++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_FATAL(conn != NULL);

        /* the h3 connection takes its callbacks from the ALPN's context */
        if (conn->alpn) {
            xqc_free(conn->alpn);
        }
        conn->alpn_len = strlen(XQC_ALPN_H3);
        conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
        xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

        xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
            XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
        CU_ASSERT_FATAL(stream != NULL);

        xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
        CU_ASSERT_FATAL(h3c != NULL);
        h3c->h3_ext_bs_callbacks.bs_read_notify =
            xqc_test_h3_ext_bytestream_read;

        xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
            XQC_H3_STREAM_TYPE_BYTESTEAM, NULL);
        CU_ASSERT_FATAL(h3s != NULL);

        xqc_h3_ext_bytestream_t *bs =
            xqc_h3_ext_bytestream_create_passive(h3c, h3s, NULL);
        CU_ASSERT_FATAL(bs != NULL);

        xqc_test_h3_ext_bytestream_queue_msg(bs, one, 1);
        xqc_test_h3_ext_bytestream_queue_msg(bs, two, 2);

        xqc_test_bs_read_cnt = 0;
        xqc_test_bs_read_len = 0;
        xqc_test_bs_read_ret = fail ? -XQC_EPARAM : 0;

        xqc_int_t ret = xqc_h3_ext_bytestream_notify_read(bs);
        if (fail) {
            /* the first message fails the read: the second one stays */
            CU_ASSERT(ret == -XQC_EPARAM);
            CU_ASSERT(xqc_test_bs_read_cnt == 1);
            CU_ASSERT(xqc_test_bs_read_len == 5);

        } else {
            CU_ASSERT(ret == XQC_OK);
            CU_ASSERT(xqc_test_bs_read_cnt == 2);
            CU_ASSERT(xqc_test_bs_read_len == 11);
        }

        xqc_h3_stream_destroy(h3s);
        xqc_h3_conn_destroy(h3c);
        xqc_destroy_stream(stream);
        xqc_engine_destroy(conn->engine);
    }
}
