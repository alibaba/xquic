/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "src/http3/frame/xqc_h3_frame.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/qpack/xqc_qpack.h"
#include "src/transport/xqc_stream.h"
#include "src/http3/qpack/stable/xqc_stable.h"

#include "xqc_common_test.h"


ssize_t xqc_h3_stream_write_data_to_buffer(xqc_h3_stream_t *h3s, unsigned char* data, uint64_t data_size, uint8_t fin);
xqc_int_t xqc_decoder_copy_header(xqc_http_header_t *hdr, xqc_var_buf_t *name, xqc_var_buf_t *value);


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
    settings.qpack_max_table_capacity = 40;

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
        CU_ASSERT(name[i] == ((char*) header.name.iov_base)[i]);
    }
    CU_ASSERT(header.value.iov_len == strlen(value));
    for (int i = 0; i < header.value.iov_len; i++) {
        CU_ASSERT(value[i] == ((char*) header.value.iov_base)[i]);
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

    xqc_stream_t *stream = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID, XQC_CLI_UNI, NULL);
    CU_ASSERT(stream != NULL);

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT(h3c != NULL);

    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream, XQC_H3_STREAM_TYPE_CONTROL, NULL);
    CU_ASSERT(h3s != NULL);

    conn->engine->eng_flag &= XQC_CONN_FLAG_CANNOT_DESTROY;

    char data[] = {"sdfjldksjf ldsjflkejwrfmmsldfpodsjcdsl;ml;fdsl;fkdlk"};
    size_t data_size = strlen(data);
    conn->conn_flag &= XQC_CONN_FLAG_CANNOT_DESTROY;
    ssize_t n_write = xqc_h3_stream_write_data_to_buffer(h3s, data, data_size, XQC_TRUE);
    CU_ASSERT(n_write == data_size);

    xqc_h3_stream_destroy(h3s);
    xqc_h3_conn_destroy(h3c);
    xqc_destroy_stream(stream);
}
