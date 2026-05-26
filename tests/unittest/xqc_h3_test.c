/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "xquic/xqc_errno.h"
#include "src/http3/frame/xqc_h3_frame.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_request.h"
#include "src/http3/xqc_h3_header.h"
#include "src/http3/qpack/xqc_qpack.h"
#include "src/transport/xqc_stream.h"
#include "src/http3/qpack/stable/xqc_stable.h"

#include "xqc_common_test.h"


ssize_t xqc_h3_stream_write_data_to_buffer(xqc_h3_stream_t *h3s, unsigned char *data, uint64_t data_size, uint8_t fin);
xqc_int_t xqc_decoder_copy_header(xqc_http_header_t *hdr, xqc_var_buf_t *name, xqc_var_buf_t *value);
/* not exposed in xqc_h3_stream.h, but stable file-scope entry used by tests */
xqc_int_t xqc_h3_stream_process_in(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len, xqc_bool_t fin_flag);


ssize_t
xqc_test_frame_parse(const char *p, size_t sz, xqc_h3_frame_pctx_t *state)
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
xqc_test_frame()
{
    uint64_t push_id = 10;
    char data[] = {"sdfjldksjf ldsjflkejwrfmmsldfpodsjcdsl;ml;fdsl;fkdlk"};
    uint64_t size = strlen(data);
    xqc_var_buf_t *header = xqc_var_buf_create(size);
    xqc_var_buf_save_data(header, data, size);
    xqc_var_buf_t *push_promise = xqc_var_buf_create(size);
    xqc_var_buf_save_data(push_promise, data, size);

    xqc_h3_conn_settings_t settings;
    settings.max_field_section_size = 10;
    settings.max_pushes = 20;
    settings.qpack_blocked_streams = 30;
    settings.qpack_enc_max_table_capacity = 40;
    settings.qpack_dec_max_table_capacity = 40;

    xqc_list_head_t send_buf;
    xqc_init_list_head(&send_buf);

    xqc_h3_frame_pctx_t pctx;
    memset(&pctx, 0, sizeof(xqc_h3_frame_pctx_t));
    ssize_t processed;

    /* write */
    /* write cancel_push frame */
    xqc_int_t ret = xqc_h3_frm_write_cancel_push(&send_buf, push_id, XQC_TRUE);
    CU_ASSERT(ret == XQC_OK);
    /* write headers frame */
    ret = xqc_h3_frm_write_headers(&send_buf, header, XQC_TRUE);
    CU_ASSERT(ret == XQC_OK);
    /* write data frame */
    ret = xqc_h3_frm_write_data(&send_buf, data, size, XQC_TRUE);
    CU_ASSERT(ret == XQC_OK);
    /* write push_promise frame */
    ret = xqc_h3_frm_write_push_promise(&send_buf, push_id, push_promise, XQC_TRUE);
    CU_ASSERT(ret == XQC_OK);
    /* write goaway frame */
    ret = xqc_h3_frm_write_goaway(&send_buf, push_id, XQC_TRUE);
    CU_ASSERT(ret == XQC_OK);
    /* write max_push_id frame */
    ret = xqc_h3_frm_write_max_push_id(&send_buf, push_id, XQC_TRUE);
    CU_ASSERT(ret == XQC_OK);
    /* write settings frame */
    ret = xqc_h3_frm_write_settings(&send_buf, &settings, XQC_TRUE);
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
    /* parse cancel_push frame */
    processed = xqc_test_frame_parse(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, &pctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_END);
    CU_ASSERT(pctx.frame.frame_payload.cancel_push.push_id.vi == push_id);
    buf->consumed_len += processed;
    xqc_h3_frm_reset_pctx(&pctx);
    /* parse headers frame */
    processed = xqc_test_frame_parse(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, &pctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_PAYLOAD);
    buf->consumed_len += processed + pctx.frame.len;
    xqc_h3_frm_reset_pctx(&pctx);
    /* parse data frame */
    processed = xqc_test_frame_parse(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, &pctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_PAYLOAD);
    buf->consumed_len += processed + pctx.frame.len;
    xqc_h3_frm_reset_pctx(&pctx);
    /* parse push_promise frame */
    processed = xqc_test_frame_parse(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, &pctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_END);
    CU_ASSERT(pctx.frame.frame_payload.push_promise.push_id.vi == push_id);
    CU_ASSERT(pctx.frame.frame_payload.push_promise.encoded_field_section != NULL);
    if (pctx.frame.frame_payload.push_promise.encoded_field_section != NULL) {
        for (int i = 0; i < strlen(data); i++) {
            CU_ASSERT(data[i] == pctx.frame.frame_payload.push_promise.encoded_field_section->data[i]);
        }
    }
    buf->consumed_len += processed;
    xqc_h3_frm_reset_pctx(&pctx);
    /* parse goaway frame */
    processed = xqc_test_frame_parse(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, &pctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_END);
    CU_ASSERT(pctx.frame.frame_payload.goaway.stream_id.vi == push_id);
    buf->consumed_len += processed;
    xqc_h3_frm_reset_pctx(&pctx);
    /* parse max_push_id frame */
    processed = xqc_test_frame_parse(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, &pctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_END);
    CU_ASSERT(pctx.frame.frame_payload.max_push_id.push_id.vi == push_id);
    buf->consumed_len += processed;
    xqc_h3_frm_reset_pctx(&pctx);
    /* parse settings frame */
    processed = xqc_test_frame_parse(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, &pctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_END);
    buf->consumed_len += processed;
    CU_ASSERT(buf->consumed_len == buf->data_len);
    xqc_h3_frm_reset_pctx(&pctx);

    /* reserved frame type with 10 bytes */
    char reserved_frame[] = "\xcf\x25\x7c\x52\x89\x59\xd7\xba\x0a\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    size_t reserved_frame_len = sizeof(reserved_frame) - 1;
    size_t reserved_consumed_len = 0;
    for (size_t i = 0; i < reserved_frame_len; i++) {
        processed = xqc_h3_frm_parse(reserved_frame + reserved_consumed_len, 1, &pctx);
        CU_ASSERT(processed > 0);
        reserved_consumed_len += processed;
    }
    CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_END);
    CU_ASSERT(reserved_consumed_len == reserved_frame_len);
    CU_ASSERT(pctx.frame.type == 0xf257c528959d7ba)
    xqc_h3_frm_reset_pctx(&pctx);

    xqc_var_buf_free(buf);
}

void
xqc_test_ins()
{
    xqc_int_t ret;
    ssize_t processed;
    xqc_flag_t t = 1;
    uint64_t index = 100;
    uint64_t stream_id = 3;
    uint64_t increment = 4;
    char name[] = {"test_name"};
    char value[] = {"test_value"};

    xqc_ins_enc_ctx_t *enc_ctx = xqc_ins_encoder_ctx_create();
    xqc_ins_dec_ctx_t *dec_ctx = xqc_ins_decoder_ctx_create();
    xqc_var_buf_t *buf = xqc_var_buf_create(XQC_VAR_BUF_INIT_SIZE);

    /* write Set Dynamic Table Capacity */
    uint64_t capacity = 50;
    ret = xqc_ins_write_set_dtable_cap(buf, capacity);
    CU_ASSERT(ret == XQC_OK);
    /* write Insert With Name Reference */
    ret = xqc_ins_write_insert_name_ref(buf, t, index, value, strlen(value));
    CU_ASSERT(ret == XQC_OK);
    /* write Insert With Literal Name */
    ret = xqc_ins_write_insert_literal_name(buf, name, strlen(name), value, strlen(value));
    CU_ASSERT(ret == XQC_OK);
    /* write Duplicate */
    ret = xqc_ins_write_dup(buf, index);
    CU_ASSERT(ret == XQC_OK);
    /* write Section Acknowledgement */
    ret = xqc_ins_write_section_ack(buf, stream_id);
    CU_ASSERT(ret == XQC_OK);
    /* write Stream Cancellation */
    ret = xqc_ins_write_stream_cancel(buf, stream_id);
    CU_ASSERT(ret == XQC_OK);
    /* write Insert Count Increment */
    ret = xqc_ins_write_icnt_increment(buf, increment);
    CU_ASSERT(ret == XQC_OK);

    /* parse Set Dynamic Table Capacity */
    processed = xqc_ins_parse_encoder(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, enc_ctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(enc_ctx->type == XQC_INS_TYPE_ENC_SET_DTABLE_CAP);
    CU_ASSERT(capacity == enc_ctx->capacity.value);
    buf->consumed_len += processed;
    /* parse Insert With Name Reference */
    processed = xqc_ins_parse_encoder(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, enc_ctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(enc_ctx->type == XQC_INS_TYPE_ENC_INSERT_NAME_REF);
    CU_ASSERT(index == enc_ctx->name_index.value);
    CU_ASSERT(strlen(value) == enc_ctx->value->value->data_len);
    for (int i = 0; i < strlen(value); i++) {
        CU_ASSERT(value[i] == enc_ctx->value->value->data[i]);
    }
    buf->consumed_len += processed;
    /* parse Insert With Literal Name */
    processed = xqc_ins_parse_encoder(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, enc_ctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(enc_ctx->type == XQC_INS_TYPE_ENC_INSERT_LITERAL);
    CU_ASSERT(strlen(name) == enc_ctx->name->value->data_len);
    for (int i = 0; i < strlen(name); i++) {
        CU_ASSERT(name[i] == enc_ctx->name->value->data[i]);
    }
    CU_ASSERT(strlen(value) == enc_ctx->value->value->data_len);
    for (int i = 0; i < strlen(value); i++) {
        CU_ASSERT(value[i] == enc_ctx->value->value->data[i]);
    }
    buf->consumed_len += processed;
    /* parse Duplicate */
    processed = xqc_ins_parse_encoder(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, enc_ctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(enc_ctx->type == XQC_INS_TYPE_ENC_DUP);
    CU_ASSERT(index == enc_ctx->name_index.value);
    buf->consumed_len += processed;
    /* parse Section Acknowledgement */
    processed = xqc_ins_parse_decoder(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, dec_ctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(dec_ctx->type == XQC_INS_TYPE_DEC_SECTION_ACK);
    CU_ASSERT(dec_ctx->stream_id.value == stream_id);
    buf->consumed_len += processed;
    /* parse Stream Cancellation */
    processed = xqc_ins_parse_decoder(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, dec_ctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(dec_ctx->type == XQC_INS_TYPE_DEC_STREAM_CANCEL);
    CU_ASSERT(dec_ctx->stream_id.value == stream_id);
    buf->consumed_len += processed;
    /* parse Insert Count Increment */
    processed = xqc_ins_parse_decoder(buf->data + buf->consumed_len, buf->data_len - buf->consumed_len, dec_ctx);
    CU_ASSERT(processed > 0);
    CU_ASSERT(dec_ctx->type == XQC_INS_TYPE_DEC_INSERT_CNT_INC);
    CU_ASSERT(dec_ctx->increment.value == increment);
    buf->consumed_len += processed;
    CU_ASSERT(buf->consumed_len == buf->data_len);

    xqc_var_buf_free(buf);
    xqc_ins_encoder_ctx_free(enc_ctx);
    xqc_ins_decoder_ctx_free(dec_ctx);
}

void
xqc_test_rep()
{
    xqc_var_buf_t *buf = xqc_var_buf_create(XQC_VAR_BUF_INIT_SIZE);
    char name[] = {"test_name"};
    char value[] = {"test_value"};
    uint64_t max_entries = 110;
    uint64_t ric = 102;
    uint64_t insert_count = 100;
    uint64_t base = 101;
    uint64_t index_1 = 102;
    uint64_t index_2 = 0;
    uint64_t index_3 = 5;
    xqc_rep_ctx_t *ctx = xqc_rep_ctx_create(0);

    /* ric >= base */
    ssize_t ret = xqc_rep_write_prefix(buf, max_entries, ric, base);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_rep_write_indexed_pb(buf, xqc_abs2pbrel(base, index_1));
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_rep_write_indexed(buf, XQC_DTABLE_FLAG, xqc_abs2brel(base, index_2));
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_rep_write_indexed(buf, XQC_STABLE_FLAG, index_3);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_rep_write_literal_name_value(buf, 1, strlen(name), name, strlen(value), value);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_rep_write_literal_with_pb_name_ref(buf, 1, xqc_abs2pbrel(base, index_1), strlen(value), value);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_rep_write_literal_with_name_ref(buf, 1, XQC_DTABLE_FLAG, xqc_abs2brel(base, index_2), strlen(value), value);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_rep_write_literal_with_name_ref(buf, 1, XQC_STABLE_FLAG, index_3, strlen(value), value);
    CU_ASSERT(ret == XQC_OK);

    ssize_t processed = xqc_rep_decode_prefix(ctx, max_entries, insert_count,  buf->data + buf->consumed_len, buf->data_len - buf->consumed_len);
    CU_ASSERT(processed > 0);
    CU_ASSERT(ctx->state == XQC_REP_DECODE_STATE_OPCODE);
    CU_ASSERT(ctx->sign > 0);
    CU_ASSERT(ctx->ric.value == ric);
    CU_ASSERT(ctx->base.value == base);
    buf->consumed_len += processed;

    processed = xqc_rep_decode_field_line(ctx, buf->data + buf->consumed_len, buf->data_len - buf->consumed_len);
    CU_ASSERT(processed > 0);
    CU_ASSERT(ctx->state == XQC_REP_DECODE_STATE_FINISH);
    CU_ASSERT(ctx->type == XQC_REP_TYPE_POST_BASE_INDEXED);
    CU_ASSERT(ctx->table == XQC_DTABLE_FLAG);
    CU_ASSERT(ctx->index.value == index_1);
    buf->consumed_len += processed;
    xqc_rep_ctx_clear_rep(ctx);

    processed = xqc_rep_decode_field_line(ctx, buf->data + buf->consumed_len, buf->data_len - buf->consumed_len);
    CU_ASSERT(processed > 0);
    CU_ASSERT(ctx->state == XQC_REP_DECODE_STATE_FINISH);
    CU_ASSERT(ctx->type == XQC_REP_TYPE_INDEXED);
    CU_ASSERT(ctx->table == XQC_DTABLE_FLAG);
    CU_ASSERT(ctx->index.value == index_2);
    buf->consumed_len += processed;
    xqc_rep_ctx_clear_rep(ctx);

    processed = xqc_rep_decode_field_line(ctx, buf->data + buf->consumed_len, buf->data_len - buf->consumed_len);
    CU_ASSERT(processed > 0);
    CU_ASSERT(ctx->state == XQC_REP_DECODE_STATE_FINISH);
    CU_ASSERT(ctx->type == XQC_REP_TYPE_INDEXED);
    CU_ASSERT(ctx->table == XQC_STABLE_FLAG);
    CU_ASSERT(ctx->index.value == index_3);
    buf->consumed_len += processed;
    xqc_rep_ctx_clear_rep(ctx);

    processed = xqc_rep_decode_field_line(ctx, buf->data + buf->consumed_len, buf->data_len - buf->consumed_len);
    CU_ASSERT(processed > 0);
    CU_ASSERT(ctx->state == XQC_REP_DECODE_STATE_FINISH);
    CU_ASSERT(ctx->type == XQC_REP_TYPE_LITERAL);
    CU_ASSERT(ctx->name->value->data_len == strlen(name));
    for (int i = 0; i < strlen(name); i++) {
        CU_ASSERT(name[i] == ctx->name->value->data[i]);
    }
    CU_ASSERT(ctx->value->value->data_len == strlen(value));
    for (int i = 0; i < strlen(value); i++) {
        CU_ASSERT(value[i] == ctx->value->value->data[i]);
    }
    buf->consumed_len += processed;

    xqc_http_header_t header;
    ret = xqc_decoder_copy_header(&header, ctx->name->value, ctx->value->value);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ctx->name->value->data == NULL);
    CU_ASSERT(ctx->value->value->data == NULL);
    xqc_rep_ctx_clear_rep(ctx);
    CU_ASSERT(header.name.iov_len == strlen(name));
    for (int i = 0; i < header.name.iov_len; i++) {
        CU_ASSERT(name[i] == ((char *) header.name.iov_base)[i]);
    }
    CU_ASSERT(header.value.iov_len == strlen(value));
    for (int i = 0; i < header.value.iov_len; i++) {
        CU_ASSERT(value[i] == ((char *) header.value.iov_base)[i]);
    }

    processed = xqc_rep_decode_field_line(ctx, buf->data + buf->consumed_len, buf->data_len - buf->consumed_len);
    CU_ASSERT(processed > 0);
    CU_ASSERT(ctx->state == XQC_REP_DECODE_STATE_FINISH);
    CU_ASSERT(ctx->type == XQC_REP_TYPE_POST_BASE_NAME_REFERENCE);
    CU_ASSERT(ctx->index.value == index_1);
    CU_ASSERT(ctx->value->value->data_len == strlen(value));
    for (int i = 0; i < strlen(value); i++) {
        CU_ASSERT(value[i] == ctx->value->value->data[i]);
    }
    buf->consumed_len += processed;
    xqc_rep_ctx_clear_rep(ctx);

    processed = xqc_rep_decode_field_line(ctx, buf->data + buf->consumed_len, buf->data_len - buf->consumed_len);
    CU_ASSERT(processed > 0);
    CU_ASSERT(ctx->state == XQC_REP_DECODE_STATE_FINISH);
    CU_ASSERT(ctx->type == XQC_REP_TYPE_NAME_REFERENCE);
    CU_ASSERT(ctx->table == XQC_DTABLE_FLAG);
    CU_ASSERT(ctx->index.value == index_2);
    CU_ASSERT(ctx->value->value->data_len == strlen(value));
    for (int i = 0; i < strlen(value); i++) {
        CU_ASSERT(value[i] == ctx->value->value->data[i]);
    }
    buf->consumed_len += processed;
    xqc_rep_ctx_clear_rep(ctx);

    processed = xqc_rep_decode_field_line(ctx, buf->data + buf->consumed_len, buf->data_len - buf->consumed_len);
    CU_ASSERT(processed > 0);
    CU_ASSERT(ctx->state == XQC_REP_DECODE_STATE_FINISH);
    CU_ASSERT(ctx->type == XQC_REP_TYPE_NAME_REFERENCE);
    CU_ASSERT(ctx->table == XQC_STABLE_FLAG);
    CU_ASSERT(ctx->index.value == index_3);
    CU_ASSERT(ctx->value->value->data_len == strlen(value));
    for (int i = 0; i < strlen(value); i++) {
        CU_ASSERT(value[i] == ctx->value->value->data[i]);
    }
    buf->consumed_len += processed;
    xqc_rep_ctx_clear_rep(ctx);

    /* ric < base */
    base = 102;
    xqc_rep_ctx_clear(ctx);
    ret = xqc_rep_write_prefix(buf, max_entries, ric, base);
    CU_ASSERT(ret == XQC_OK);
    processed = xqc_rep_decode_prefix(ctx, max_entries, insert_count, buf->data + buf->consumed_len, buf->data_len - buf->consumed_len);
    CU_ASSERT(processed > 0);
    CU_ASSERT(ctx->sign == 0);
    CU_ASSERT(ctx->ric.value == ric);
    CU_ASSERT(ctx->base.value == base);
    buf->consumed_len += processed;
    CU_ASSERT(buf->consumed_len == buf->data_len);

    xqc_var_buf_free(buf);
    xqc_rep_ctx_free(ctx);
}

void
xqc_test_stream()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    /* set alpn to H3 */
    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    xqc_stream_t *stream = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID, XQC_CLI_UNI, NULL, NULL);
    CU_ASSERT(stream != NULL);

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT(h3c != NULL);

    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream, XQC_H3_STREAM_TYPE_CONTROL, NULL);
    CU_ASSERT(h3s != NULL);

    char data[] = {"sdfjldksjf ldsjflkejwrfmmsldfpodsjcdsl;ml;fdsl;fkdlk"};
    size_t data_size = strlen(data);

    ssize_t n_write = xqc_h3_stream_write_data_to_buffer(h3s, data, data_size, XQC_TRUE);
    CU_ASSERT(n_write == data_size);

    xqc_h3_stream_destroy(h3s);
    xqc_h3_conn_destroy(h3c);
    xqc_destroy_stream(stream);

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
}


extern int xqc_h3_stream_close_notify(xqc_stream_t *stream, void *user_data);

/*
 * Drive xqc_h3_stream_close_notify against the matrix of stream types and
 * teardown guards required by RFC 9114 6.2.1 and RFC 9204 4.2. Each case
 * builds a fresh transport stream + h3 stream so the close_notify path runs
 * end-to-end. The h3 stream is forced into the QPACK-blocked + READ_EOF
 * branch so the function returns before destroying h3s, which lets the test
 * own teardown and inspect conn->conn_err / conn->conn_flag.
 */

typedef struct {
    const char     *name;
    uint64_t        stream_type;
    xqc_bool_t      set_closing_notify;
    xqc_bool_t      set_state_closing;
    uint64_t        pre_conn_err;
    uint64_t        expected_conn_err;
    xqc_bool_t      expect_error_flag;
} xqc_h3_critical_close_case_t;

static void
xqc_h3_critical_run_case(xqc_connection_t *conn, xqc_h3_conn_t *h3c,
    const xqc_h3_critical_close_case_t *tc)
{
    /*
     * reset just enough connection state for this case. the stream must
     * be allocated while conn_state < CLOSING (xqc_create_stream_with_conn
     * rejects otherwise), so the CLOSING-state guard is applied AFTER
     * the stream is up.
     */
    conn->conn_err   = tc->pre_conn_err;
    conn->conn_flag &= ~(XQC_CONN_FLAG_ERROR | XQC_CONN_FLAG_CLOSING_NOTIFY);
    conn->conn_state = XQC_CONN_STATE_ESTABED;

    xqc_stream_t *stream = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                                       XQC_CLI_UNI, NULL, NULL);
    CU_ASSERT_FATAL(stream != NULL);

    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
                                                (xqc_h3_stream_type_t)tc->stream_type,
                                                NULL);
    CU_ASSERT_FATAL(h3s != NULL);

    /* now apply the per-case teardown guards so the close_notify path
     * sees the same state a real teardown would expose. */
    if (tc->set_closing_notify) {
        conn->conn_flag |= XQC_CONN_FLAG_CLOSING_NOTIFY;
    }
    if (tc->set_state_closing) {
        conn->conn_state = XQC_CONN_STATE_CLOSING;
    }

    /*
     * make close_notify return before destroying h3s so the test owns
     * teardown; this branch needs READ_EOF + QPACK_DECODE_BLOCKED and no
     * ACTIVELY_CLOSED.
     */
    h3s->flags |= XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED
                | XQC_HTTP3_STREAM_FLAG_READ_EOF;

    int ret = xqc_h3_stream_close_notify(stream, h3s);
    CU_ASSERT(ret == XQC_OK);

    if (tc->expected_conn_err == H3_CLOSED_CRITICAL_STREAM) {
        CU_ASSERT(conn->conn_err == H3_CLOSED_CRITICAL_STREAM);
    } else {
        CU_ASSERT(conn->conn_err == tc->expected_conn_err);
    }

    if (tc->expect_error_flag) {
        CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    } else {
        CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);
    }

    /*
     * close_notify nulled h3s->stream and the test owns teardown from here.
     * Mark the transport stream as DISCARDED so xqc_destroy_stream does
     * not redrive stream_close_notify on the soon-to-be-freed h3s.
     */
    stream->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
    xqc_h3_stream_destroy(h3s);
    xqc_destroy_stream(stream);
}

void
xqc_test_h3_critical_stream_close()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT_FATAL(h3c != NULL);

    /* lift the local uni-stream send limit so all cases can create a stream */
    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 1024;

    xqc_h3_critical_close_case_t cases[] = {
        /* control stream peer-close on a healthy connection */
        { "control_running",        XQC_H3_STREAM_TYPE_CONTROL,
          XQC_FALSE, XQC_FALSE, 0, H3_CLOSED_CRITICAL_STREAM, XQC_TRUE },
        /* qpack encoder stream peer-close on a healthy connection */
        { "qpack_encoder_running",  XQC_H3_STREAM_TYPE_QPACK_ENCODER,
          XQC_FALSE, XQC_FALSE, 0, H3_CLOSED_CRITICAL_STREAM, XQC_TRUE },
        /* qpack decoder stream peer-close on a healthy connection */
        { "qpack_decoder_running",  XQC_H3_STREAM_TYPE_QPACK_DECODER,
          XQC_FALSE, XQC_FALSE, 0, H3_CLOSED_CRITICAL_STREAM, XQC_TRUE },
        /* request stream close must not raise the critical-stream error */
        { "request_running",        XQC_H3_STREAM_TYPE_REQUEST,
          XQC_FALSE, XQC_FALSE, 0, 0, XQC_FALSE },
        /* push stream close must not raise the critical-stream error */
        { "push_running",           XQC_H3_STREAM_TYPE_PUSH,
          XQC_FALSE, XQC_FALSE, 0, 0, XQC_FALSE },
        /* unknown stream type must not raise the critical-stream error */
        { "unknown_running",        XQC_H3_STREAM_TYPE_UNKNOWN,
          XQC_FALSE, XQC_FALSE, 0, 0, XQC_FALSE },
        /* connection already issued CONNECTION_CLOSE - report is suppressed */
        { "control_closing_notify", XQC_H3_STREAM_TYPE_CONTROL,
          XQC_TRUE, XQC_FALSE, 0, 0, XQC_FALSE },
        /* connection state already CLOSING - report is suppressed */
        { "control_state_closing",  XQC_H3_STREAM_TYPE_CONTROL,
          XQC_FALSE, XQC_TRUE, 0, 0, XQC_FALSE },
        /* a previous conn_err must win (XQC_H3_CONN_ERR is first-write-wins) */
        { "control_preserve_err",   XQC_H3_STREAM_TYPE_CONTROL,
          XQC_FALSE, XQC_FALSE, 0xdead, 0xdead, XQC_FALSE },
    };

    size_t n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        xqc_h3_critical_run_case(conn, h3c, &cases[i]);
    }

    xqc_h3_conn_destroy(h3c);

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
}


/*
 * Tests for issue #608: RFC 9114 Section 6.2.1 + RFC 9204 Section 4.2
 * single-instance unidirectional stream duplicate detection.
 *
 * xqc_h3_conn_on_uni_stream_created must:
 *   - Accept first CONTROL/QPACK_ENCODER/QPACK_DECODER (set creation flag)
 *   - Reject second instance with H3_STREAM_CREATION_ERROR (0x103)
 *   - Reject PUSH with H3_ID_ERROR (0x108) since xquic does not support push
 *
 * Each sub-case uses a fresh test_engine_connect() for state isolation.
 */

static void
xqc_test_h3_second_stream_one(uint64_t stype, uint64_t expected_err_second)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT_FATAL(h3c != NULL);

    /* baseline: no error */
    CU_ASSERT(conn->conn_err == 0);

    /* first instance: should be accepted */
    xqc_int_t ret = xqc_h3_conn_on_uni_stream_created(h3c, stype);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    /* second instance: must be rejected */
    ret = xqc_h3_conn_on_uni_stream_created(h3c, stype);
    CU_ASSERT(ret == -XQC_H3_INVALID_STREAM);
    CU_ASSERT(conn->conn_err == expected_err_second);
    CU_ASSERT(conn->conn_err == 0x103);  /* literal H3_STREAM_CREATION_ERROR */
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_h3_conn_destroy(h3c);
    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
}

static void
xqc_test_h3_push_stream_rejected(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT_FATAL(h3c != NULL);

    CU_ASSERT(conn->conn_err == 0);

    /*
     * PUSH stream: xquic does not support server push, so even the first
     * push stream must be rejected with H3_ID_ERROR (0x108).
     * RFC 9114 Section 4.6 / Section 6.2.2
     */
    xqc_int_t ret = xqc_h3_conn_on_uni_stream_created(h3c,
            XQC_H3_STREAM_TYPE_PUSH);
    CU_ASSERT(ret == -XQC_H3_INVALID_STREAM);
    CU_ASSERT(conn->conn_err == H3_ID_ERROR);
    CU_ASSERT(conn->conn_err == 0x108);  /* literal H3_ID_ERROR */
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_h3_conn_destroy(h3c);
    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
}

void
xqc_test_h3_second_control_stream_rejected()
{
    /* Case 1: second CONTROL stream -> H3_STREAM_CREATION_ERROR
     * per RFC 9114 Section 6.2.1 */
    xqc_test_h3_second_stream_one(XQC_H3_STREAM_TYPE_CONTROL,
            H3_STREAM_CREATION_ERROR);

    /* Case 2: second QPACK_ENCODER stream -> H3_STREAM_CREATION_ERROR
     * per RFC 9204 Section 4.2 */
    xqc_test_h3_second_stream_one(XQC_H3_STREAM_TYPE_QPACK_ENCODER,
            H3_STREAM_CREATION_ERROR);

    /* Case 3: second QPACK_DECODER stream -> H3_STREAM_CREATION_ERROR
     * per RFC 9204 Section 4.2 */
    xqc_test_h3_second_stream_one(XQC_H3_STREAM_TYPE_QPACK_DECODER,
            H3_STREAM_CREATION_ERROR);

    /* Case 4: PUSH stream (unsupported) -> H3_ID_ERROR
     * per RFC 9114 Section 4.6 / 6.2.2 */
    xqc_test_h3_push_stream_rejected();
}


/*
 * RFC 9114 Section 4.2.2: the size of a field list is the sum of the
 * uncompressed name and value lengths plus 32 bytes per field.
 */
void
xqc_test_h3_uncompressed_fields_size()
{
    xqc_http_headers_t hdrs;
    hdrs.headers  = NULL;
    hdrs.capacity = 0;

    /* empty list */
    hdrs.count     = 0;
    hdrs.total_len = 0;
    CU_ASSERT_EQUAL(xqc_h3_uncompressed_fields_size(&hdrs), 0);

    /* zero-length fields still cost 32B each */
    hdrs.count     = 3;
    hdrs.total_len = 0;
    CU_ASSERT_EQUAL(xqc_h3_uncompressed_fields_size(&hdrs), 96);

    /* single field */
    hdrs.count     = 1;
    hdrs.total_len = 10;
    CU_ASSERT_EQUAL(xqc_h3_uncompressed_fields_size(&hdrs), 42);

    /* many fields */
    hdrs.count     = 5;
    hdrs.total_len = 100;
    CU_ASSERT_EQUAL(xqc_h3_uncompressed_fields_size(&hdrs), 260);

    /*
     * Issue 751 regression: total_len <= limit but the per-field 32B
     * overhead pushes the field-section size above the limit. The pre-fix
     * receive path compared total_len only and would have accepted this.
     */
    hdrs.count     = 1;
    hdrs.total_len = 80;
    CU_ASSERT(hdrs.total_len <= 100);
    CU_ASSERT(xqc_h3_uncompressed_fields_size(&hdrs) > 100);
}


/*
 * Drive xqc_h3_request_on_recv_header against the
 * SETTINGS_MAX_FIELD_SECTION_SIZE check to prove it now uses
 * total_len + count*32 (RFC 9114 4.2.2) symmetrically with the send side.
 */
void
xqc_test_h3_recv_header_field_section_size()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT_FATAL(h3c != NULL);

    /* override the default 32K limit so boundaries are easy to reason about */
    h3c->local_h3_conn_settings.max_field_section_size = 100;

    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 16;

    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
                                                       XQC_UNDEFINE_STREAM_ID,
                                                       XQC_CLI_UNI, NULL, NULL);
    CU_ASSERT_FATAL(stream != NULL);

    /* CONTROL stream type avoids xqc_h3_stream_destroy walking into the
       request-only h3r teardown path on cleanup. */
    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
                                                XQC_H3_STREAM_TYPE_CONTROL,
                                                NULL);
    CU_ASSERT_FATAL(h3s != NULL);

    xqc_h3_request_t *h3r = xqc_calloc(1, sizeof(xqc_h3_request_t));
    CU_ASSERT_FATAL(h3r != NULL);
    h3r->h3_stream  = h3s;
    h3r->request_if = &h3c->h3_request_callbacks;
    xqc_init_list_head(&h3r->body_buf);

    xqc_http_headers_t *hdr = &h3r->h3_header[0];
    hdr->headers  = NULL;
    hdr->capacity = 0;

    /* regression for issue 751: total_len < limit but
       total_len + count*32 > limit. Pre-fix this would have been accepted. */
    hdr->count     = 1;
    hdr->total_len = 80;
    h3r->current_header = 0;
    h3r->read_flag      = 0;
    ret = xqc_h3_request_on_recv_header(h3r);
    CU_ASSERT_EQUAL(ret, -XQC_H3_INVALID_HEADER);

    /* exact-equal-to-limit must be accepted (check is strictly greater) */
    hdr->count     = 2;
    hdr->total_len = 36;
    h3r->current_header = 0;
    h3r->read_flag      = 0;
    ret = xqc_h3_request_on_recv_header(h3r);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    /* one byte over the limit must be rejected */
    hdr->count     = 2;
    hdr->total_len = 37;
    h3r->current_header = 0;
    h3r->read_flag      = 0;
    ret = xqc_h3_request_on_recv_header(h3r);
    CU_ASSERT_EQUAL(ret, -XQC_H3_INVALID_HEADER);

    /* zero-field headers under the limit are accepted */
    hdr->count     = 0;
    hdr->total_len = 50;
    h3r->current_header = 0;
    h3r->read_flag      = 0;
    ret = xqc_h3_request_on_recv_header(h3r);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    for (size_t i = 0; i < XQC_H3_REQUEST_MAX_HEADERS_CNT; i++) {
        xqc_h3_headers_free(&h3r->h3_header[i]);
    }
    xqc_list_buf_list_free(&h3r->body_buf);
    xqc_free(h3r);

    h3s->h3r = NULL;
    stream->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
    xqc_h3_stream_destroy(h3s);
    xqc_destroy_stream(stream);

    xqc_h3_conn_destroy(h3c);

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
}


/*
 * Tests for issue #744: RFC 9114 §4.1.2 / §8.1
 *
 * The fix changes two H3 error-code mappings in xqc_h3_stream.c:
 *   1. xqc_h3_stream_process_in: when the bidi pipeline surfaces
 *      -XQC_H3_INVALID_HEADER (header section too large, third HEADERS
 *      frame, ...), the wire-level code must be H3_MESSAGE_ERROR
 *      (0x10E), not the generic H3_GENERAL_PROTOCOL_ERROR (0x101).
 *      RFC 9114 §4.1.2 requires "malformed request or response"
 *      to be treated as H3_MESSAGE_ERROR.
 *   2. xqc_h3_stream_process_request: when our request-side header
 *      buffer slot count (XQC_H3_REQUEST_MAX_HEADERS_CNT = 2) is
 *      exhausted, that's an implementation limit, not malformed
 *      peer input, so the wire-level code must be H3_INTERNAL_ERROR
 *      (0x102) per RFC 9114 §8.1.
 *
 * Helpers below build a request-bidi h3 stream with no transport I/O
 * so the tests can call xqc_h3_stream_process_in directly.
 */

/* Minimal valid QPACK encoded field section wrapped in a HEADERS frame:
 *   01     HEADERS frame type        (varint)
 *   03     payload length 3          (varint)
 *   00     Required Insert Count 0   (QPACK prefix, 8-bit)
 *   00     S=0, Delta Base 0         (QPACK prefix, 7-bit)
 *   c0     Indexed Field Line, static table idx 0 (":authority","")
 *           decoded section length = 10 (name) + 0 (value) = 10 bytes
 */
static const unsigned char xqc_h3_msgerr_valid_headers[] = {
    0x01, 0x03, 0x00, 0x00, 0xC0
};


static xqc_h3_stream_t *
xqc_h3_msgerr_setup(xqc_connection_t **out_conn, xqc_h3_conn_t **out_h3c)
{
    xqc_connection_t *conn = test_engine_connect();
    if (conn == NULL) {
        return NULL;
    }

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    /* allow stream creation without negotiated peer limits */
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 1024;
    conn->conn_state = XQC_CONN_STATE_ESTABED;

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    if (h3c == NULL) {
        return NULL;
    }

    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
            XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    if (stream == NULL) {
        return NULL;
    }

    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
            XQC_H3_STREAM_TYPE_REQUEST, NULL);
    if (h3s == NULL) {
        return NULL;
    }

    /* eagerly create the request so tests can manipulate current_header
     * before feeding bytes through process_in. */
    h3s->h3r = xqc_h3_request_create_inner(h3c, h3s, NULL);
    if (h3s->h3r == NULL) {
        return NULL;
    }

    *out_conn = conn;
    *out_h3c = h3c;
    return h3s;
}

static void
xqc_h3_msgerr_teardown(xqc_h3_stream_t *h3s, xqc_h3_conn_t *h3c,
    xqc_connection_t *conn)
{
    xqc_stream_t *stream = h3s->stream;
    /* h3 stream owns h3r lifetime; mark stream DISCARDED so destroy
     * does not redrive close_notify on the soon-to-be-freed h3s. */
    stream->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
    xqc_h3_stream_destroy(h3s);
    xqc_destroy_stream(stream);
    xqc_h3_conn_destroy(h3c);
    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
}


void
xqc_test_h3_message_error_enum()
{
    CU_ASSERT(H3_MESSAGE_ERROR == 0x10E);
}


void
xqc_test_h3_message_error_code_value()
{
    /*
     * IANA-registered HTTP/3 error code points (RFC 9114 §8.1 Table 2).
     * The wire format is frozen by these literal values; any drift
     * breaks interoperability. Lock the relevant entries plus the
     * two adjacent code points so an accidental table reorder fails.
     */
    CU_ASSERT(H3_GENERAL_PROTOCOL_ERROR == 0x101);
    CU_ASSERT(H3_INTERNAL_ERROR         == 0x102);
    CU_ASSERT(H3_REQUEST_INCOMPLETE     == 0x10D);
    CU_ASSERT(H3_MESSAGE_ERROR          == 0x10E);
    CU_ASSERT(H3_CONNECT_ERROR          == 0x10F);
}


void
xqc_test_h3_forbidden_headers_rejected()
{
    /* transfer-encoding: always forbidden */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"transfer-encoding", 17,
        (const unsigned char *)"chunked", 7) == XQC_TRUE);

    /* keep-alive: always forbidden */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"keep-alive", 10,
        (const unsigned char *)"timeout=5", 9) == XQC_TRUE);

    /* proxy-connection: always forbidden */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"proxy-connection", 16,
        (const unsigned char *)"keep-alive", 10) == XQC_TRUE);

    /* te with non-trailers value: forbidden */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"te", 2,
        (const unsigned char *)"chunked", 7) == XQC_TRUE);

    /* te with non-trailers value in mixed case: still forbidden */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"te", 2,
        (const unsigned char *)"Chunked", 7) == XQC_TRUE);
}


void
xqc_test_h3_malformed_headers_uses_message_error()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    /*
     * Shrink the locally advertised SETTINGS_MAX_FIELD_SECTION_SIZE so
     * the decoded :authority header section (10 bytes) trips the
     * "header section too large" path in xqc_h3_request_on_recv_header
     * (xqc_h3_request.c:821). That returns -XQC_H3_INVALID_HEADER up
     * to process_in, which must map it to H3_MESSAGE_ERROR per
     * RFC 9114 §4.1.2. Pre-fix this raised H3_GENERAL_PROTOCOL_ERROR.
     */
    h3c->local_h3_conn_settings.max_field_section_size = 1;

    CU_ASSERT(conn->conn_err == 0);

    unsigned char buf[sizeof(xqc_h3_msgerr_valid_headers)];
    xqc_memcpy(buf, xqc_h3_msgerr_valid_headers, sizeof(buf));

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, buf, sizeof(buf),
            XQC_TRUE);

    /* process_in collapses sub-errors to -XQC_H3_EPROC_REQUEST */
    CU_ASSERT(ret == -XQC_H3_EPROC_REQUEST);
    CU_ASSERT(conn->conn_err == H3_MESSAGE_ERROR);
    CU_ASSERT(conn->conn_err == 0x10E);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_headers_capacity_uses_internal_error()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    /*
     * Simulate two prior HEADERS sections (request + trailer) by
     * jumping current_header to the cap. A third HEADERS frame then
     * makes xqc_h3_request_get_writing_headers return NULL inside
     * xqc_h3_stream_process_request (xqc_h3_stream.c:920), which is
     * an implementation-side capacity exhaustion. Post-fix this must
     * be H3_INTERNAL_ERROR (0x102), not the previous
     * H3_GENERAL_PROTOCOL_ERROR (0x101). XQC_H3_CONN_ERR is
     * first-write-wins so the outer process_in mapping at line 1521
     * does not overwrite it.
     */
    h3s->h3r->current_header = XQC_H3_REQUEST_MAX_HEADERS_CNT;

    CU_ASSERT(conn->conn_err == 0);

    unsigned char buf[sizeof(xqc_h3_msgerr_valid_headers)];
    xqc_memcpy(buf, xqc_h3_msgerr_valid_headers, sizeof(buf));

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, buf, sizeof(buf),
            XQC_TRUE);

    CU_ASSERT(ret == -XQC_H3_EPROC_REQUEST);
    CU_ASSERT(conn->conn_err == H3_INTERNAL_ERROR);
    CU_ASSERT(conn->conn_err == 0x102);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_valid_headers_smoke()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    /* Default max_field_section_size leaves a 10-byte section well
     * under cap; no error code must be set. Guards against the fix
     * accidentally tagging the happy path. */
    CU_ASSERT(conn->conn_err == 0);

    unsigned char buf[sizeof(xqc_h3_msgerr_valid_headers)];
    xqc_memcpy(buf, xqc_h3_msgerr_valid_headers, sizeof(buf));

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, buf, sizeof(buf),
            XQC_TRUE);

    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);
    /* the HEADERS frame should have advanced the request to 1 section */
    CU_ASSERT(h3s->h3r->current_header == 1);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_frame_parse_error_uses_frame_error()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    /*
     * Feed a HEADERS frame whose QPACK payload references static
     * table index 99 (out of range, valid is 0..98). The QPACK
     * decoder fails with -XQC_QPACK_SAVE_HEADERS_ERROR (not
     * -XQC_H3_INVALID_HEADER), so process_in must keep the wire
     * code as H3_FRAME_ERROR. This is the line 1524 "else" branch
     * the PR does NOT change - regression guard against the fix
     * accidentally widening H3_MESSAGE_ERROR to non-header errors.
     *
     *   01           HEADERS frame type
     *   04           payload length 4
     *   00           Required Insert Count 0       (QPACK prefix, 8-bit)
     *   00           S=0, Delta Base 0             (QPACK prefix, 7-bit)
     *   ff 24        Indexed Field Line, T=1 (static), 6-bit prefix
     *                with continuation: idx = 63 + 36 = 99 (out of range)
     */
    const unsigned char malformed[] = { 0x01, 0x04, 0x00, 0x00, 0xFF, 0x24 };
    unsigned char buf[sizeof(malformed)];
    xqc_memcpy(buf, malformed, sizeof(buf));

    CU_ASSERT(conn->conn_err == 0);

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, buf, sizeof(buf),
            XQC_TRUE);

    CU_ASSERT(ret < 0);
    CU_ASSERT(conn->conn_err == H3_FRAME_ERROR);
    CU_ASSERT(conn->conn_err != H3_MESSAGE_ERROR);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


/*
 * Issue #612: RFC 9114 §7.2.1/§7.2.5 — DATA, HEADERS, PUSH_PROMISE on
 * the control stream MUST be rejected with H3_FRAME_UNEXPECTED.
 *
 * The frame parser does not consume payload for DATA/HEADERS (state stays
 * at PAYLOAD, never reaches END), so the rejection guard must fire before
 * the state==END dispatch.  PUSH_PROMISE payload IS consumed to END but
 * was previously swallowed by the default: branch.
 */

static xqc_h3_stream_t *
xqc_h3_ctrl_test_setup(xqc_connection_t **out_conn, xqc_h3_conn_t **out_h3c)
{
    xqc_connection_t *conn = test_engine_connect();
    if (conn == NULL) {
        return NULL;
    }

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 1024;
    conn->conn_state = XQC_CONN_STATE_ESTABED;

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    if (h3c == NULL) {
        return NULL;
    }

    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
            XQC_UNDEFINE_STREAM_ID, XQC_CLI_UNI, NULL, NULL);
    if (stream == NULL) {
        return NULL;
    }

    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
            XQC_H3_STREAM_TYPE_CONTROL, NULL);
    if (h3s == NULL) {
        return NULL;
    }

    *out_conn = conn;
    *out_h3c = h3c;
    return h3s;
}

static void
xqc_h3_ctrl_test_teardown(xqc_h3_stream_t *h3s, xqc_h3_conn_t *h3c,
    xqc_connection_t *conn)
{
    xqc_stream_t *stream = h3s->stream;
    stream->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
    xqc_h3_stream_destroy(h3s);
    xqc_destroy_stream(stream);
    xqc_h3_conn_destroy(h3c);
    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
}

/*
 * Feed a valid SETTINGS frame so subsequent tests start from a state
 * where SETTINGS_RECVED is set.
 * SETTINGS: type=0x04, len=0x02, entry=[id=0x06(MAX_FIELD_SECTION_SIZE), val=0x00]
 */
static ssize_t
xqc_h3_ctrl_feed_settings(xqc_h3_stream_t *h3s)
{
    unsigned char settings[] = { 0x04, 0x02, 0x06, 0x00 };
    return xqc_h3_stream_process_control(h3s, settings, sizeof(settings));
}

/* Case 1: DATA frame (with payload) rejected on control stream */
static void
xqc_test_h3_ctrl_reject_data(void)
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    ssize_t ret = xqc_h3_ctrl_feed_settings(h3s);
    CU_ASSERT_FATAL(ret > 0);

    /* DATA frame: type=0x00, len=0x03, payload="abc" */
    unsigned char data_frame[] = { 0x00, 0x03, 0x61, 0x62, 0x63 };
    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    ssize_t processed = xqc_h3_stream_process_control(h3s, data_frame,
            sizeof(data_frame));

    CU_ASSERT(processed == -XQC_H3_CONTROL_FRAME_UNEXPECTED);
    CU_ASSERT(conn->conn_err == H3_FRAME_UNEXPECTED);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}

/* Case 2: zero-length DATA frame rejected on control stream */
static void
xqc_test_h3_ctrl_reject_zero_len_data(void)
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    ssize_t ret = xqc_h3_ctrl_feed_settings(h3s);
    CU_ASSERT_FATAL(ret > 0);

    /* DATA frame: type=0x00, len=0x00 (zero-length) */
    unsigned char zero_data[] = { 0x00, 0x00 };
    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    ssize_t processed = xqc_h3_stream_process_control(h3s, zero_data,
            sizeof(zero_data));

    CU_ASSERT(processed == -XQC_H3_CONTROL_FRAME_UNEXPECTED);
    CU_ASSERT(conn->conn_err == H3_FRAME_UNEXPECTED);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}

/* Case 3: HEADERS frame rejected on control stream */
static void
xqc_test_h3_ctrl_reject_headers(void)
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    ssize_t ret = xqc_h3_ctrl_feed_settings(h3s);
    CU_ASSERT_FATAL(ret > 0);

    /* HEADERS frame: type=0x01, len=0x02, payload=0x00 0x00 */
    unsigned char headers_frame[] = { 0x01, 0x02, 0x00, 0x00 };
    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    ssize_t processed = xqc_h3_stream_process_control(h3s, headers_frame,
            sizeof(headers_frame));

    CU_ASSERT(processed == -XQC_H3_CONTROL_FRAME_UNEXPECTED);
    CU_ASSERT(conn->conn_err == H3_FRAME_UNEXPECTED);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}

/* Case 4: PUSH_PROMISE frame rejected on control stream (RFC 9114 §7.2.5) */
static void
xqc_test_h3_ctrl_reject_push_promise(void)
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    ssize_t ret = xqc_h3_ctrl_feed_settings(h3s);
    CU_ASSERT_FATAL(ret > 0);

    /* PUSH_PROMISE: type=0x05, len=0x02, push_id=0x00, field_section=0x00 */
    unsigned char push_promise[] = { 0x05, 0x02, 0x00, 0x00 };
    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    ssize_t processed = xqc_h3_stream_process_control(h3s, push_promise,
            sizeof(push_promise));

    CU_ASSERT(processed == -XQC_H3_CONTROL_FRAME_UNEXPECTED);
    CU_ASSERT(conn->conn_err == H3_FRAME_UNEXPECTED);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}

/*
 * Case 5: DATA without SETTINGS_RECVED — the illegal-frame guard takes
 * precedence over the SETTINGS-first guard.
 */
static void
xqc_test_h3_ctrl_reject_data_before_settings(void)
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    /* Do NOT feed SETTINGS — SETTINGS_RECVED flag stays unset */
    unsigned char data_frame[] = { 0x00, 0x02, 0xAA, 0xBB };
    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    ssize_t processed = xqc_h3_stream_process_control(h3s, data_frame,
            sizeof(data_frame));

    CU_ASSERT(processed == -XQC_H3_CONTROL_FRAME_UNEXPECTED);
    CU_ASSERT(conn->conn_err == H3_FRAME_UNEXPECTED);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}

/*
 * Case 6: GOAWAY || DATA in one buffer — GOAWAY side effects land first,
 * then DATA is still rejected.
 */
static void
xqc_test_h3_ctrl_goaway_then_data(void)
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    ssize_t ret = xqc_h3_ctrl_feed_settings(h3s);
    CU_ASSERT_FATAL(ret > 0);

    /*
     * GOAWAY: type=0x07, len=0x01, stream_id=0x04
     * DATA:   type=0x00, len=0x01, payload=0xFF
     */
    unsigned char buf[] = { 0x07, 0x01, 0x04, 0x00, 0x01, 0xFF };
    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    ssize_t processed = xqc_h3_stream_process_control(h3s, buf, sizeof(buf));

    /* GOAWAY side effects must have landed */
    CU_ASSERT((h3c->flags & XQC_H3_CONN_FLAG_GOAWAY_RECVD) != 0);
    CU_ASSERT(h3c->goaway_stream_id == 4);

    /* DATA must be rejected */
    CU_ASSERT(processed == -XQC_H3_CONTROL_FRAME_UNEXPECTED);
    CU_ASSERT(conn->conn_err == H3_FRAME_UNEXPECTED);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}

/*
 * Case 7: partial feed — type byte in first call, length in second.
 * Verifies multi-call parse continuity still rejects correctly.
 */
static void
xqc_test_h3_ctrl_reject_partial_feed(void)
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    ssize_t ret = xqc_h3_ctrl_feed_settings(h3s);
    CU_ASSERT_FATAL(ret > 0);

    /* Feed only the type byte of a DATA frame */
    unsigned char type_byte[] = { 0x00 };
    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    ssize_t processed = xqc_h3_stream_process_control(h3s, type_byte,
            sizeof(type_byte));
    /* Parser consumed the type byte, state is LEN, no error yet */
    CU_ASSERT(processed == 1);
    CU_ASSERT(conn->conn_err == 0);

    /* Feed the length byte — parser enters PAYLOAD and guard fires */
    unsigned char len_byte[] = { 0x02 };
    processed = xqc_h3_stream_process_control(h3s, len_byte, sizeof(len_byte));

    CU_ASSERT(processed == -XQC_H3_CONTROL_FRAME_UNEXPECTED);
    CU_ASSERT(conn->conn_err == H3_FRAME_UNEXPECTED);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}

/* Case 8: GOAWAY regression — valid GOAWAY still works after the fix */
static void
xqc_test_h3_ctrl_goaway_regression(void)
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    ssize_t ret = xqc_h3_ctrl_feed_settings(h3s);
    CU_ASSERT_FATAL(ret > 0);

    /* GOAWAY: type=0x07, len=0x01, stream_id=0x08 */
    unsigned char goaway[] = { 0x07, 0x01, 0x08 };
    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    ssize_t processed = xqc_h3_stream_process_control(h3s, goaway,
            sizeof(goaway));

    CU_ASSERT(processed == (ssize_t)sizeof(goaway));
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((h3c->flags & XQC_H3_CONN_FLAG_GOAWAY_RECVD) != 0);
    CU_ASSERT(h3c->goaway_stream_id == 8);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}

/* Public entry point that runs all sub-cases */
void
xqc_test_h3_control_frame_unexpected(void)
{
    xqc_test_h3_ctrl_reject_data();
    xqc_test_h3_ctrl_reject_zero_len_data();
    xqc_test_h3_ctrl_reject_headers();
    xqc_test_h3_ctrl_reject_push_promise();
    xqc_test_h3_ctrl_reject_data_before_settings();
    xqc_test_h3_ctrl_goaway_then_data();
    xqc_test_h3_ctrl_reject_partial_feed();
    xqc_test_h3_ctrl_goaway_regression();
}



/*
 * Issue #607 - RFC 9114 §6.2.1: "If the first frame of the control stream
 * is any other frame type, this MUST be treated as a connection error of
 * type H3_MISSING_SETTINGS."
 *
 * Note: DATA/HEADERS/PUSH_PROMISE are caught earlier by the §7.2.1/§7.2.5
 * guard (issue #612) with H3_FRAME_UNEXPECTED, so this test covers only
 * the frame types that reach the SETTINGS-first gate: CANCEL_PUSH, GOAWAY,
 * MAX_PUSH_ID, and reserved/grease types.
 */
static void
xqc_test_h3_missing_settings_one(uint64_t frame_type)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT_FATAL(h3c != NULL);

    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
            XQC_UNDEFINE_STREAM_ID, XQC_CLI_UNI, NULL, NULL);
    CU_ASSERT_FATAL(stream != NULL);

    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
            XQC_H3_STREAM_TYPE_CONTROL, NULL);
    CU_ASSERT_FATAL(h3s != NULL);

    /* ensure SETTINGS_RECVED is NOT set */
    h3c->flags &= ~XQC_H3_CONN_FLAG_SETTINGS_RECVED;
    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    /*
     * Build a minimal frame: [type varint][length=0].
     * All standard H3 types fit in a single byte varint.
     */
    unsigned char frame_buf[2];
    frame_buf[0] = (unsigned char)(frame_type & 0x3F);  /* 1-byte varint */
    frame_buf[1] = 0x00;  /* length = 0 */

    ssize_t processed = xqc_h3_stream_process_control(h3s, frame_buf,
            sizeof(frame_buf));

    CU_ASSERT(processed == -XQC_H3_MISSING_SETTINGS);
    CU_ASSERT(conn->conn_err == H3_MISSING_SETTINGS);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    stream->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
    xqc_h3_stream_destroy(h3s);
    xqc_destroy_stream(stream);
    xqc_h3_conn_destroy(h3c);
    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
}

void
xqc_test_h3_missing_settings()
{
    /* CANCEL_PUSH (0x03) */
    xqc_test_h3_missing_settings_one(XQC_H3_FRM_CANCEL_PUSH);

    /* GOAWAY (0x07) */
    xqc_test_h3_missing_settings_one(XQC_H3_FRM_GOAWAY);

    /* MAX_PUSH_ID (0x0d) */
    xqc_test_h3_missing_settings_one(XQC_H3_FRM_MAX_PUSH_ID);

    /* reserved/grease type (0x21) */
    xqc_test_h3_missing_settings_one(0x21);
}


/*
 * Tests for issue #609: RFC 9114 Section 7.2.3/7.2.4/7.2.6/7.2.7
 *
 * Control-only frames (SETTINGS, CANCEL_PUSH, GOAWAY, MAX_PUSH_ID)
 * received on an HTTP/3 request stream MUST be rejected with
 * H3_FRAME_UNEXPECTED (0x0105) connection error.
 *
 * The fix adds an explicit case block in xqc_h3_stream_process_request
 * (xqc_h3_stream.c) that catches these four frame types and returns
 * -XQC_H3_REQUEST_FRAME_UNEXPECTED after setting the connection error
 * via XQC_H3_CONN_ERR.
 *
 * Each sub-case builds a fresh request-bidi h3 stream, feeds a minimal
 * frame (type varint + length=0 varint), and checks the result.
 */

static void
xqc_test_h3_request_frame_unexpected_one(uint64_t frame_type,
    xqc_bool_t expect_reject)
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    /* baseline: clean connection state */
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    /*
     * Build a minimal frame: [type varint][length=0 varint].
     * All tested frame types fit in a single-byte varint (<=0x3F).
     * Length=0 means the frame body is empty; the frame parser will
     * still enter PAYLOAD state, which is enough for the
     * process_request switch to dispatch on the type.
     */
    unsigned char frame_buf[2];
    frame_buf[0] = (unsigned char)(frame_type & 0x3F);
    frame_buf[1] = 0x00;  /* length = 0 */

    ssize_t processed = xqc_h3_stream_process_request(h3s, frame_buf,
            sizeof(frame_buf), XQC_FALSE);

    if (expect_reject) {
        /* must return the new internal error code */
        CU_ASSERT(processed == -XQC_H3_REQUEST_FRAME_UNEXPECTED);
        /* must set the wire-level H3_FRAME_UNEXPECTED (0x0105) */
        CU_ASSERT(conn->conn_err == H3_FRAME_UNEXPECTED);
        CU_ASSERT(conn->conn_err == 0x0105);
        /* must set the error flag so CONNECTION_CLOSE is sent */
        CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    } else {
        /* must NOT return the frame-unexpected error */
        CU_ASSERT(processed != -XQC_H3_REQUEST_FRAME_UNEXPECTED);
        /* must NOT set H3_FRAME_UNEXPECTED */
        CU_ASSERT(conn->conn_err != H3_FRAME_UNEXPECTED);
    }

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_request_frame_unexpected()
{
    /*
     * ===== Positive cases: control-only frames MUST be rejected =====
     *
     * RFC 9114 Section 7.2.4: SETTINGS on request stream
     * RFC 9114 Section 7.2.3: CANCEL_PUSH on request stream
     * RFC 9114 Section 7.2.6: GOAWAY on request stream
     * RFC 9114 Section 7.2.7: MAX_PUSH_ID on request stream
     */

    /* Case 1: SETTINGS (0x04) on request stream */
    xqc_test_h3_request_frame_unexpected_one(XQC_H3_FRM_SETTINGS, XQC_TRUE);
    CU_ASSERT(XQC_H3_FRM_SETTINGS == 0x04);

    /* Case 2: CANCEL_PUSH (0x03) on request stream */
    xqc_test_h3_request_frame_unexpected_one(XQC_H3_FRM_CANCEL_PUSH, XQC_TRUE);
    CU_ASSERT(XQC_H3_FRM_CANCEL_PUSH == 0x03);

    /* Case 3: GOAWAY (0x07) on request stream */
    xqc_test_h3_request_frame_unexpected_one(XQC_H3_FRM_GOAWAY, XQC_TRUE);
    CU_ASSERT(XQC_H3_FRM_GOAWAY == 0x07);

    /* Case 4: MAX_PUSH_ID (0x0D) on request stream */
    xqc_test_h3_request_frame_unexpected_one(XQC_H3_FRM_MAX_PUSH_ID, XQC_TRUE);
    CU_ASSERT(XQC_H3_FRM_MAX_PUSH_ID == 0x0D);


    /*
     * ===== Negative cases: request-stream frames MUST NOT be rejected =====
     *
     * DATA and HEADERS are valid on request streams. Verify the fix
     * does not accidentally widen the rejection to legitimate frames.
     */

    /* Case 5: DATA (0x00) on request stream -- must be accepted */
    xqc_test_h3_request_frame_unexpected_one(XQC_H3_FRM_DATA, XQC_FALSE);

    /* Case 6: HEADERS (0x01) on request stream -- must be accepted */
    xqc_test_h3_request_frame_unexpected_one(XQC_H3_FRM_HEADERS, XQC_FALSE);


    /*
     * ===== Edge case: unknown frame type =====
     *
     * RFC 9114 Section 9: "Implementations MUST ignore... frames
     * having a type that is not yet defined." An unknown frame on a
     * request stream must be silently ignored, NOT rejected.
     *
     * Type 0x15 is not assigned in the H3 frame type registry.
     */

    /* Case 7: Unknown frame type (0x15) on request stream -- must be ignored */
    xqc_test_h3_request_frame_unexpected_one(0x15, XQC_FALSE);


    /*
     * ===== Wire-level error code value lock =====
     *
     * IANA HTTP/3 error code registry (RFC 9114 Section 8.1 Table 2).
     * H3_FRAME_UNEXPECTED = 0x0105 is frozen; any drift breaks interop.
     */
    CU_ASSERT(H3_FRAME_UNEXPECTED == 0x0105);

    /*
     * Internal error code lock: XQC_H3_REQUEST_FRAME_UNEXPECTED = 833
     * must be in the H3 error range (>= XQC_H3_EMALLOC = 800) for
     * XQC_H3_CONN_ERR to fire.
     */
    CU_ASSERT(XQC_H3_REQUEST_FRAME_UNEXPECTED == 835);
    CU_ASSERT(XQC_H3_REQUEST_FRAME_UNEXPECTED >= XQC_H3_EMALLOC);
}


void
xqc_test_h3_allowed_headers_pass()
{
    /* content-type: normal header, never forbidden */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"content-type", 12,
        (const unsigned char *)"text/html", 9) == XQC_FALSE);

    /* te with value "trailers": RFC exception, allowed */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"te", 2,
        (const unsigned char *)"trailers", 8) == XQC_FALSE);

    /* te with value "Trailers" (mixed case): QPACK sends lowercase, reject non-exact */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"te", 2,
        (const unsigned char *)"Trailers", 8) == XQC_TRUE);

    /* te with value "TRAILERS" (all caps): same reasoning */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"te", 2,
        (const unsigned char *)"TRAILERS", 8) == XQC_TRUE);

    /* connection: allowed for WebSocket-over-HTTP/3 (Connection: Upgrade) */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"connection", 10,
        (const unsigned char *)"Upgrade", 7) == XQC_FALSE);

    /* upgrade: allowed for WebSocket-over-HTTP/3 (Upgrade: websocket) */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"upgrade", 7,
        (const unsigned char *)"websocket", 9) == XQC_FALSE);

    /* host: normal header */
    CU_ASSERT(xqc_h3_hdr_is_forbidden(
        (const unsigned char *)"host", 4,
        (const unsigned char *)"example.com", 11) == XQC_FALSE);
}


/*
 * Issue #748 regression test.
 *
 * RFC 9114 4.2 says any request or response containing uppercase
 * characters in field names MUST be treated as malformed, and 4.1.2
 * routes malformed messages to a stream error of type H3_MESSAGE_ERROR.
 * The xquic encoder already silently lowercases on send, but the
 * receiver had no check at all -- xqc_qpack_dec_headers handed any
 * decoded header straight to the application without validating the
 * name was lowercase. This test exercises the new helper that powers
 * the receive-side guard.
 *
 * The helper is a pure byte scan, so the test drives it directly
 * with stack-allocated names rather than going through QPACK encoding.
 * Pseudo-header names (which start with ':') go through the same
 * scan: ':' is 0x3A which sits below 'A' = 0x41, so a pseudo-header
 * name like ":Method" is caught on the 'M', exactly the same path
 * as a regular field.
 */
void
xqc_test_h3_field_name_uppercase_rejection()
{
    /* all-lowercase regular field name -> accepted */
    const unsigned char ua_lc[] = "user-agent";
    CU_ASSERT(xqc_qpack_field_name_has_uppercase(ua_lc, sizeof(ua_lc) - 1)
              == XQC_FALSE);

    /* mixed case regular field name -> rejected */
    const unsigned char ua_mc[] = "User-Agent";
    CU_ASSERT(xqc_qpack_field_name_has_uppercase(ua_mc, sizeof(ua_mc) - 1)
              == XQC_TRUE);

    /* single uppercase byte -> rejected */
    const unsigned char single_u[] = "X";
    CU_ASSERT(xqc_qpack_field_name_has_uppercase(single_u, sizeof(single_u) - 1)
              == XQC_TRUE);

    /* all-uppercase -> rejected */
    const unsigned char all_u[] = "ACCEPT";
    CU_ASSERT(xqc_qpack_field_name_has_uppercase(all_u, sizeof(all_u) - 1)
              == XQC_TRUE);

    /* empty name -> accepted (the helper is name-only; empty-name
     * malformed handling lives elsewhere) */
    CU_ASSERT(xqc_qpack_field_name_has_uppercase((const unsigned char *)"", 0)
              == XQC_FALSE);

    /* lowercase pseudo-header -> accepted */
    const unsigned char pseudo_lc[] = ":method";
    CU_ASSERT(xqc_qpack_field_name_has_uppercase(pseudo_lc, sizeof(pseudo_lc) - 1)
              == XQC_FALSE);

    /* uppercase in pseudo-header -> rejected (RFC 9114 4.3 routes
     * this through "undefined pseudo-header" but the byte scan
     * catches it first) */
    const unsigned char pseudo_uc[] = ":Method";
    CU_ASSERT(xqc_qpack_field_name_has_uppercase(pseudo_uc, sizeof(pseudo_uc) - 1)
              == XQC_TRUE);

    /* boundary characters around A-Z -> not flagged */
    const unsigned char at_sign[] = "@";  /* 0x40, just below 'A' */
    CU_ASSERT(xqc_qpack_field_name_has_uppercase(at_sign, sizeof(at_sign) - 1)
              == XQC_FALSE);
    const unsigned char open_bracket[] = "[";  /* 0x5B, just above 'Z' */
    CU_ASSERT(xqc_qpack_field_name_has_uppercase(open_bracket,
                                                 sizeof(open_bracket) - 1)
              == XQC_FALSE);

    /* high-bit byte (0xff) -> not flagged. Such a byte is invalid in
     * an HTTP/3 field name per RFC 9110 token rules, but that is a
     * separate validation -- the helper is scoped to A-Z. */
    const unsigned char high_bit[] = { 0xff, 0x00 };
    CU_ASSERT(xqc_qpack_field_name_has_uppercase(high_bit, 1) == XQC_FALSE);

    /* uppercase deep inside an otherwise lowercase name -> rejected.
     * Catches the off-by-one of an early-exit-only-on-first-byte loop. */
    const unsigned char trailing_uc[] = "x-forwarded-For";
    CU_ASSERT(xqc_qpack_field_name_has_uppercase(trailing_uc,
                                                 sizeof(trailing_uc) - 1)
              == XQC_TRUE);
}
