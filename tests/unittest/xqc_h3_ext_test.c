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
        ssize_t ret = xqc_h3_frm_parse(p + offset, len, state);
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