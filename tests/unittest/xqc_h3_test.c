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
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_utils.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_packet.h"
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
xqc_test_h3_single_vint_frame_valid()
{
    const unsigned char frames[][4] = {
        { XQC_H3_FRM_CANCEL_PUSH, 0x02, 0x40, 0x01 },
        { XQC_H3_FRM_GOAWAY, 0x02, 0x40, 0x04 },
        { XQC_H3_FRM_MAX_PUSH_ID, 0x02, 0x40, 0x01 },
    };
    const uint64_t types[] = {
        XQC_H3_FRM_CANCEL_PUSH,
        XQC_H3_FRM_GOAWAY,
        XQC_H3_FRM_MAX_PUSH_ID,
    };

    for (size_t i = 0; i < sizeof(frames) / sizeof(frames[0]); i++) {
        xqc_h3_frame_pctx_t pctx;
        memset(&pctx, 0, sizeof(pctx));

        ssize_t processed = xqc_h3_frm_parse(frames[i], 3, &pctx);
        CU_ASSERT(processed == 3);
        CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_PAYLOAD);
        CU_ASSERT(pctx.frame.consumed_len == 1);

        processed = xqc_h3_frm_parse(frames[i] + 3, 1, &pctx);
        CU_ASSERT(processed == 1);
        CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_END);
        CU_ASSERT(pctx.frame.type == types[i]);
        CU_ASSERT(pctx.frame.len == 2);
        CU_ASSERT(pctx.frame.consumed_len == 2);

        xqc_h3_frm_reset_pctx(&pctx);
    }
}


void
xqc_test_h3_single_vint_frame_length_error()
{
    const unsigned char overlong[][7] = {
        { XQC_H3_FRM_CANCEL_PUSH, 0x05, 0x40, 0x01, 0x21, 0x01, 0x00 },
        { XQC_H3_FRM_GOAWAY, 0x05, 0x40, 0x04, 0x21, 0x01, 0x00 },
        { XQC_H3_FRM_MAX_PUSH_ID, 0x05, 0x40, 0x01, 0x21, 0x01, 0x00 },
    };
    const unsigned char short_payload[][4] = {
        { XQC_H3_FRM_CANCEL_PUSH, 0x01, 0x40, 0x01 },
        { XQC_H3_FRM_GOAWAY, 0x01, 0x40, 0x04 },
        { XQC_H3_FRM_MAX_PUSH_ID, 0x01, 0x40, 0x01 },
    };

    for (size_t i = 0; i < sizeof(overlong) / sizeof(overlong[0]); i++) {
        xqc_h3_frame_pctx_t pctx;
        memset(&pctx, 0, sizeof(pctx));

        ssize_t processed = xqc_h3_frm_parse(overlong[i], 3, &pctx);
        CU_ASSERT(processed == 3);
        CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_PAYLOAD);
        CU_ASSERT(pctx.frame.consumed_len == 1);

        processed = xqc_h3_frm_parse(overlong[i] + 3,
                                     sizeof(overlong[i]) - 3, &pctx);
        CU_ASSERT(processed == -XQC_H3_DECODE_ERROR);
        CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_PAYLOAD);
        CU_ASSERT(pctx.frame.consumed_len == 2);

        xqc_h3_frm_reset_pctx(&pctx);
    }

    for (size_t i = 0;
         i < sizeof(short_payload) / sizeof(short_payload[0]); i++)
    {
        xqc_h3_frame_pctx_t pctx;
        memset(&pctx, 0, sizeof(pctx));

        ssize_t processed = xqc_h3_frm_parse(short_payload[i],
                                             sizeof(short_payload[i]), &pctx);
        CU_ASSERT(processed == -XQC_H3_DECODE_ERROR);
        CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_PAYLOAD);
        CU_ASSERT(pctx.frame.consumed_len == 2);

        xqc_h3_frm_reset_pctx(&pctx);
    }
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
        CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err)
                  == H3_CLOSED_CRITICAL_STREAM);
    } else {
        CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err)
                  == tc->expected_conn_err);
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
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == expected_err_second);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == 0x103);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_h3_conn_destroy(h3c);
    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
}

static void
xqc_test_h3_push_stream_rejected(xqc_conn_type_t conn_type,
    uint64_t expected_err)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    conn->conn_type = conn_type;

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT_FATAL(h3c != NULL);

    CU_ASSERT(conn->conn_err == 0);

    xqc_int_t ret = xqc_h3_conn_on_uni_stream_created(h3c,
            XQC_H3_STREAM_TYPE_PUSH);
    CU_ASSERT(ret == -XQC_H3_INVALID_STREAM);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == expected_err);
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
}


void
xqc_test_h3_reserved_uni_stream_accepted()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    conn->conn_type = XQC_CONN_TYPE_SERVER;

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT_FATAL(h3c != NULL);

    /* RFC 9114 Section 6.2.3 requires reserved stream types to be ignored. */
    xqc_int_t ret = xqc_h3_conn_on_uni_stream_created(h3c, 0x21);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    xqc_h3_conn_destroy(h3c);
    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
}


void
xqc_test_h3_push_stream_error_codes()
{
    /*
     * RFC 9114 Section 4.6: a client that has not sent MAX_PUSH_ID must
     * close the connection with H3_ID_ERROR upon receiving any push stream.
     * XQUIC has no production path that sends MAX_PUSH_ID.
     */
    xqc_test_h3_push_stream_rejected(XQC_CONN_TYPE_CLIENT, H3_ID_ERROR);

    /*
     * RFC 9114 Section 6.2.2: a server rejects a client-initiated push
     * stream with H3_STREAM_CREATION_ERROR.
     */
    xqc_test_h3_push_stream_rejected(XQC_CONN_TYPE_SERVER,
            H3_STREAM_CREATION_ERROR);
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
    xqc_http_header_t fake_hdrs[2] = {
        {
            .name = {.iov_base = (void *)"x", .iov_len = 1},
            .value = {.iov_base = (void *)"v", .iov_len = 1},
        },
        {
            .name = {.iov_base = (void *)"y", .iov_len = 1},
            .value = {.iov_base = (void *)"v", .iov_len = 1},
        },
    };
    hdr->headers  = fake_hdrs;
    hdr->capacity = 2;

    /* regression for issue 751: total_len < limit but
       total_len + count*32 > limit. Pre-fix this would have been accepted. */
    hdr->count     = 1;
    hdr->total_len = 80;
    h3r->completed_header_count = 0;
    h3r->read_flag      = 0;
    ret = xqc_h3_request_on_recv_header(h3r);
    CU_ASSERT_EQUAL(ret, -XQC_H3_INVALID_HEADER);

    /* exact-equal-to-limit must be accepted (check is strictly greater) */
    hdr->count     = 2;
    hdr->total_len = 36;
    h3r->completed_header_count = 0;
    h3r->read_flag      = 0;
    ret = xqc_h3_request_on_recv_header(h3r);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    /* one byte over the limit must be rejected */
    hdr->count     = 2;
    hdr->total_len = 37;
    h3r->completed_header_count = 0;
    h3r->read_flag      = 0;
    ret = xqc_h3_request_on_recv_header(h3r);
    CU_ASSERT_EQUAL(ret, -XQC_H3_INVALID_HEADER);

    /* zero-field headers under the limit are accepted */
    hdr->count     = 0;
    hdr->total_len = 50;
    h3r->completed_header_count = 0;
    h3r->read_flag      = 0;
    ret = xqc_h3_request_on_recv_header(h3r);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    hdr->headers = NULL;
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

    /* eagerly create the request so tests can manipulate completed_header_count
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

    /*
     * RFC 9114 Section 4.1.2 makes this a stream error. process_in
     * consumes the handled parse failure after scheduling RESET_STREAM.
     */
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(h3s->stream->stream_err == H3_MESSAGE_ERROR);
    CU_ASSERT(h3s->stream->stream_err == 0x10E);
    CU_ASSERT(h3s->stream->stream_state_send
              == XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

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
     * jumping completed_header_count to the cap. A third HEADERS frame then
     * makes xqc_h3_request_get_writing_headers return NULL inside
     * xqc_h3_stream_process_request (xqc_h3_stream.c:920), which is
     * an implementation-side capacity exhaustion. Post-fix this must
     * be H3_INTERNAL_ERROR (0x102), not the previous
     * H3_GENERAL_PROTOCOL_ERROR (0x101). XQC_H3_CONN_ERR is
     * first-write-wins so the outer process_in mapping at line 1521
     * does not overwrite it.
     */
    h3s->h3r->completed_header_count = XQC_H3_REQUEST_MAX_HEADERS_CNT;

    CU_ASSERT(conn->conn_err == 0);

    unsigned char buf[sizeof(xqc_h3_msgerr_valid_headers)];
    xqc_memcpy(buf, xqc_h3_msgerr_valid_headers, sizeof(buf));

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, buf, sizeof(buf),
            XQC_TRUE);

    CU_ASSERT(ret == -XQC_H3_EPROC_REQUEST);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_INTERNAL_ERROR);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == 0x102);
    CU_ASSERT(XQC_CONN_ERR_IS_APPLICATION(conn->conn_err));
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
    CU_ASSERT(h3s->stream->stream_err == 0);
    CU_ASSERT(h3s->stream->stream_state_send
              < XQC_SEND_STREAM_ST_RESET_SENT);
    /* the HEADERS frame should have advanced the request to 1 section */
    CU_ASSERT(h3s->h3r->completed_header_count == 1);

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
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_ERROR);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) != H3_MESSAGE_ERROR);
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


static ssize_t
xqc_h3_ctrl_feed_setting(xqc_h3_stream_t *h3s, unsigned char identifier,
    unsigned char value)
{
    unsigned char settings[] = {
        XQC_H3_FRM_SETTINGS, 0x02, identifier, value
    };
    return xqc_h3_stream_process_control(h3s, settings, sizeof(settings));
}


void
xqc_test_h3_settings_accepted()
{
    const xqc_conn_type_t roles[] = {
        XQC_CONN_TYPE_CLIENT, XQC_CONN_TYPE_SERVER
    };
    const unsigned char identifiers[] = {
        XQC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
        0x08,
        0x21,
    };

    for (size_t i = 0; i < sizeof(roles) / sizeof(roles[0]); i++) {
        for (size_t j = 0;
             j < sizeof(identifiers) / sizeof(identifiers[0]); j++)
        {
            xqc_connection_t *conn = NULL;
            xqc_h3_conn_t *h3c = NULL;
            xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
            CU_ASSERT_FATAL(h3s != NULL);

            conn->conn_type = roles[i];
            ssize_t processed = xqc_h3_ctrl_feed_setting(
                h3s, identifiers[j], 1);

            CU_ASSERT(processed == 4);
            CU_ASSERT(conn->conn_err == 0);
            CU_ASSERT(h3c->flags & XQC_H3_CONN_FLAG_SETTINGS_RECVED);
            if (identifiers[j]
                == XQC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE)
            {
                CU_ASSERT(h3c->peer_h3_conn_settings.max_field_section_size
                          == 1);
            }

            xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
        }
    }
}


void
xqc_test_h3_reserved_h2_settings_rejected()
{
    const xqc_conn_type_t roles[] = {
        XQC_CONN_TYPE_CLIENT, XQC_CONN_TYPE_SERVER
    };
    const unsigned char identifiers[] = {
        XQC_H3_SETTINGS_H2_ENABLE_PUSH,
        XQC_H3_SETTINGS_H2_MAX_CONCURRENT_STREAMS,
        XQC_H3_SETTINGS_H2_INITIAL_WINDOW_SIZE,
        XQC_H3_SETTINGS_H2_MAX_FRAME_SIZE,
    };

    for (size_t i = 0; i < sizeof(roles) / sizeof(roles[0]); i++) {
        for (size_t j = 0;
             j < sizeof(identifiers) / sizeof(identifiers[0]); j++)
        {
            xqc_connection_t *conn = NULL;
            xqc_h3_conn_t *h3c = NULL;
            xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
            CU_ASSERT_FATAL(h3s != NULL);

            conn->conn_type = roles[i];
            ssize_t processed = xqc_h3_ctrl_feed_setting(
                h3s, identifiers[j], 0);

            CU_ASSERT(processed == -H3_SETTINGS_ERROR);
            CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err)
                      == H3_SETTINGS_ERROR);
            CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_ERROR);

            xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
        }
    }
}


static ssize_t
xqc_h3_ctrl_feed_max_push_id(xqc_h3_stream_t *h3s, unsigned char push_id)
{
    unsigned char frame[] = { XQC_H3_FRM_MAX_PUSH_ID, 0x01, push_id };
    return xqc_h3_stream_process_control(h3s, frame, sizeof(frame));
}


static ssize_t
xqc_h3_ctrl_feed_cancel_push(xqc_h3_stream_t *h3s, unsigned char push_id)
{
    unsigned char frame[] = { XQC_H3_FRM_CANCEL_PUSH, 0x01, push_id };
    return xqc_h3_stream_process_control(h3s, frame, sizeof(frame));
}


static ssize_t
xqc_h3_ctrl_feed_goaway(xqc_h3_stream_t *h3s, unsigned char identifier)
{
    unsigned char frame[] = { XQC_H3_FRM_GOAWAY, 0x01, identifier };
    return xqc_h3_stream_process_control(h3s, frame, sizeof(frame));
}


void
xqc_test_h3_goaway_id_valid()
{
    const xqc_conn_type_t roles[] = {
        XQC_CONN_TYPE_CLIENT, XQC_CONN_TYPE_SERVER
    };

    for (size_t i = 0; i < sizeof(roles) / sizeof(roles[0]); i++) {
        xqc_connection_t *conn = NULL;
        xqc_h3_conn_t *h3c = NULL;
        xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
        CU_ASSERT_FATAL(h3s != NULL);

        conn->conn_type = roles[i];
        CU_ASSERT_FATAL(xqc_h3_ctrl_feed_settings(h3s) > 0);

        /* RFC 9114 Section 5.2 permits equal and decreasing IDs. */
        CU_ASSERT(xqc_h3_ctrl_feed_goaway(h3s, 8) == 3);
        CU_ASSERT(xqc_h3_ctrl_feed_goaway(h3s, 4) == 3);
        CU_ASSERT(xqc_h3_ctrl_feed_goaway(h3s, 4) == 3);
        CU_ASSERT(h3c->goaway_stream_id == 4);
        CU_ASSERT(conn->conn_err == 0);
        CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

        xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
    }
}


void
xqc_test_h3_goaway_id_increase_rejected()
{
    const xqc_conn_type_t roles[] = {
        XQC_CONN_TYPE_CLIENT, XQC_CONN_TYPE_SERVER
    };

    for (size_t i = 0; i < sizeof(roles) / sizeof(roles[0]); i++) {
        xqc_connection_t *conn = NULL;
        xqc_h3_conn_t *h3c = NULL;
        xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
        CU_ASSERT_FATAL(h3s != NULL);

        conn->conn_type = roles[i];
        CU_ASSERT_FATAL(xqc_h3_ctrl_feed_settings(h3s) > 0);
        CU_ASSERT_FATAL(xqc_h3_ctrl_feed_goaway(h3s, 4) == 3);

        /* A later larger ID is an H3_ID_ERROR and cannot replace the cutoff. */
        CU_ASSERT(xqc_h3_ctrl_feed_goaway(h3s, 8)
                  == -XQC_H3_INVALID_GOAWAY_ID);
        CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_ID_ERROR);
        CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
        CU_ASSERT(h3c->goaway_stream_id == 4);
        CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);

        xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
    }
}


void
xqc_test_h3_reserved_control_frame_accepted()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    CU_ASSERT_FATAL(xqc_h3_ctrl_feed_settings(h3s) > 0);

    /*
     * RFC 9114 Section 9: the CANCEL_PUSH rejection must remain narrow;
     * an unknown reserved control frame is ignored.
     */
    unsigned char reserved[] = { 0x21, 0x01, 0x00 };
    CU_ASSERT(xqc_h3_stream_process_control(h3s, reserved,
              sizeof(reserved)) == sizeof(reserved));
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_h2_reserved_frames_rejected()
{
    const unsigned char frame_types[] = {
        XQC_H3_FRM_RESERVED_PRIORITY,
        XQC_H3_FRM_RESERVED_PING,
        XQC_H3_FRM_RESERVED_WINDOW_UPDATE,
        XQC_H3_FRM_RESERVED_CONTINUATION,
    };

    for (size_t i = 0; i < sizeof(frame_types); ++i) {
        unsigned char frame[] = { frame_types[i], 0x00 };
        xqc_h3_frame_pctx_t pctx = {0};
        xqc_h3_frm_reset_pctx(&pctx);
        CU_ASSERT(xqc_h3_frm_parse(frame, sizeof(frame), &pctx)
                  == -XQC_H3_RESERVED_FRAME_UNEXPECTED);
        CU_ASSERT(pctx.frame.type == frame_types[i]);
        CU_ASSERT(pctx.state == XQC_H3_FRM_STATE_LEN);

        xqc_connection_t *conn = NULL;
        xqc_h3_conn_t *h3c = NULL;
        xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
        CU_ASSERT_FATAL(h3s != NULL);
        CU_ASSERT_FATAL(xqc_h3_ctrl_feed_settings(h3s) > 0);

        CU_ASSERT(xqc_h3_stream_process_control(h3s, frame, sizeof(frame))
                  == -XQC_H3_RESERVED_FRAME_UNEXPECTED);
        CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
        CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
        CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);
        xqc_h3_ctrl_test_teardown(h3s, h3c, conn);

        conn = NULL;
        h3c = NULL;
        h3s = xqc_h3_msgerr_setup(&conn, &h3c);
        CU_ASSERT_FATAL(h3s != NULL);
        conn->conn_type = XQC_CONN_TYPE_SERVER;

        CU_ASSERT(xqc_h3_stream_process_in(h3s, frame, sizeof(frame),
                  XQC_FALSE) == -XQC_H3_EPROC_REQUEST);
        CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
        CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
        CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);
        xqc_h3_msgerr_teardown(h3s, h3c, conn);
    }

    CU_ASSERT(xqc_h3_frm_is_h2_reserved(0x21) == XQC_FALSE);
}


void
xqc_test_h3_cancel_push_rejected()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    CU_ASSERT_FATAL(conn->conn_type == XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(xqc_h3_ctrl_feed_settings(h3s) > 0);

    /*
     * RFC 9114 Sections 4.6 and 7.2.3: XQUIC has no production path that
     * sends MAX_PUSH_ID, so even push ID zero exceeds the unset maximum.
     */
    CU_ASSERT(xqc_h3_ctrl_feed_cancel_push(h3s, 0)
              == -XQC_H3_INVALID_CANCEL_PUSH_ID);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_ID_ERROR);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);

    conn = NULL;
    h3c = NULL;
    h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    CU_ASSERT_FATAL(xqc_h3_ctrl_feed_settings(h3s) > 0);
    CU_ASSERT_FATAL(xqc_h3_ctrl_feed_max_push_id(h3s, 5) == 3);

    /*
     * XQUIC never sends PUSH_PROMISE in production. A cancellation from the
     * client is therefore for an unmentioned push ID, even when the ID is
     * within the received MAX_PUSH_ID range.
     */
    CU_ASSERT(xqc_h3_ctrl_feed_cancel_push(h3s, 0)
              == -XQC_H3_INVALID_CANCEL_PUSH_ID);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_ID_ERROR);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_max_push_id_valid()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    CU_ASSERT_FATAL(xqc_h3_ctrl_feed_settings(h3s) > 0);

    /*
     * RFC 9114 Section 7.2.7: a server accepts MAX_PUSH_ID from a client,
     * including the first value zero, later increases, and equal values.
     */
    CU_ASSERT(xqc_h3_ctrl_feed_max_push_id(h3s, 0) == 3);
    CU_ASSERT(h3c->max_stream_id_recvd == 0);
    CU_ASSERT(xqc_h3_ctrl_feed_max_push_id(h3s, 5) == 3);
    CU_ASSERT(h3c->max_stream_id_recvd == 5);
    CU_ASSERT(xqc_h3_ctrl_feed_max_push_id(h3s, 5) == 3);
    CU_ASSERT(h3c->max_stream_id_recvd == 5);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_max_push_id_errors()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    CU_ASSERT_FATAL(conn->conn_type == XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(xqc_h3_ctrl_feed_settings(h3s) > 0);

    /* A client cannot receive MAX_PUSH_ID from a server. */
    CU_ASSERT(xqc_h3_ctrl_feed_max_push_id(h3s, 1)
              == -XQC_H3_INVALID_MAX_PUSH_ID);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3c->max_stream_id_recvd == 0);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);

    conn = NULL;
    h3c = NULL;
    h3s = xqc_h3_ctrl_test_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    CU_ASSERT_FATAL(xqc_h3_ctrl_feed_settings(h3s) > 0);
    CU_ASSERT_FATAL(xqc_h3_ctrl_feed_max_push_id(h3s, 5) == 3);

    /* A decreasing value is H3_ID_ERROR and cannot replace the maximum. */
    CU_ASSERT(xqc_h3_ctrl_feed_max_push_id(h3s, 4)
              == -XQC_H3_INVALID_MAX_PUSH_ID);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_ID_ERROR);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3c->max_stream_id_recvd == 5);

    xqc_h3_ctrl_test_teardown(h3s, h3c, conn);
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
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
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
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
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
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
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
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
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
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
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
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
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
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
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
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_MISSING_SETTINGS);
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
        CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
        CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == 0x0105);
        /* must set the error flag so CONNECTION_CLOSE is sent */
        CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    } else {
        /* must NOT return the frame-unexpected error */
        CU_ASSERT(processed != -XQC_H3_REQUEST_FRAME_UNEXPECTED);
        /* must NOT set H3_FRAME_UNEXPECTED */
        CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err)
                  != H3_FRAME_UNEXPECTED);
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


    /* HEADERS is valid on request streams. DATA validity depends on the
     * HTTP message sequence and is covered by dedicated tests below. */
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
xqc_test_h3_data_after_headers_accepted()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    unsigned char headers[sizeof(xqc_h3_msgerr_valid_headers)];
    xqc_memcpy(headers, xqc_h3_msgerr_valid_headers, sizeof(headers));
    unsigned char data[] = { XQC_H3_FRM_DATA, 0x01, 0x2a };

    ssize_t processed = xqc_h3_stream_process_request(h3s, headers,
            sizeof(headers), XQC_FALSE);
    CU_ASSERT(processed == (ssize_t)sizeof(headers));
    CU_ASSERT(h3s->h3r->completed_header_count == 1);

    processed = xqc_h3_stream_process_request(h3s, data, sizeof(data),
            XQC_FALSE);
    CU_ASSERT(processed == (ssize_t)sizeof(data));
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);
    CU_ASSERT(h3s->h3r->body_buf_count == 1);
    CU_ASSERT(!xqc_list_empty(&h3s->h3r->body_buf));

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_data_before_headers_rejected()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    /* RFC 9114 Section 4.1 requires H3_FRAME_UNEXPECTED for this sequence. */
    unsigned char data[] = { XQC_H3_FRM_DATA, 0x01, 0x2a };
    ssize_t processed = xqc_h3_stream_process_request(h3s, data,
            sizeof(data), XQC_FALSE);

    CU_ASSERT(processed == -XQC_H3_REQUEST_FRAME_UNEXPECTED);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
    CU_ASSERT(XQC_CONN_ERR_IS_APPLICATION(conn->conn_err));
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3s->h3r->completed_header_count == 0);
    CU_ASSERT(h3s->h3r->body_buf_count == 0);
    CU_ASSERT(xqc_list_empty(&h3s->h3r->body_buf));
    CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);

    /*
     * A peer-created bidi stream is initially type-unknown when extensions
     * are enabled. Exercise a complete zero-length DATA frame, which the
     * unknown-type dispatcher consumes before request-stream processing.
     */
    conn = NULL;
    h3c = NULL;
    h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);
    xqc_h3_request_destroy(h3s->h3r);
    h3s->h3r = NULL;
    h3s->type = XQC_H3_STREAM_TYPE_UNKNOWN;
    h3c->flags |= XQC_H3_CONN_FLAG_EXT_ENABLED;

    unsigned char empty_data[] = { XQC_H3_FRM_DATA, 0x00 };
    processed = xqc_h3_stream_process_in(h3s, empty_data,
            sizeof(empty_data), XQC_FALSE);

    CU_ASSERT(processed == -XQC_H3_EPROC_REQUEST);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
    CU_ASSERT(XQC_CONN_ERR_IS_APPLICATION(conn->conn_err));
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT(h3s->h3r == NULL);
    CU_ASSERT(h3s->pctx.frame_pctx.state == XQC_H3_FRM_STATE_TYPE);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_server_reserved_request_frame_accepted()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);
    conn->conn_type = XQC_CONN_TYPE_SERVER;

    /*
     * RFC 9114 Section 9 requires unknown frame types, including the
     * reserved type 0x21, to be ignored.
     */
    unsigned char reserved_frame[] = { 0x21, 0x00 };
    ssize_t processed = xqc_h3_stream_process_request(h3s, reserved_frame,
            sizeof(reserved_frame), XQC_FALSE);

    CU_ASSERT(processed == sizeof(reserved_frame));
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_server_push_promise_rejected()
{
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);
    conn->conn_type = XQC_CONN_TYPE_SERVER;

    /*
     * RFC 9114 Section 7.2.5: a server that receives PUSH_PROMISE from a
     * client must close the connection with H3_FRAME_UNEXPECTED.
     */
    unsigned char push_promise[] = { 0x05, 0x02, 0x00, 0x00 };
    ssize_t processed = xqc_h3_stream_process_request(h3s, push_promise,
            sizeof(push_promise), XQC_FALSE);

    CU_ASSERT(processed == -XQC_H3_REQUEST_FRAME_UNEXPECTED);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == 0x0105);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);

    /*
     * Cover a PUSH_PROMISE as the first frame on a peer-created bidi
     * stream. The unknown-type dispatcher parses that first frame before
     * request-stream processing, so it must enforce the same rule.
     */
    conn = NULL;
    h3c = NULL;
    h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);
    conn->conn_type = XQC_CONN_TYPE_SERVER;
    xqc_h3_request_destroy(h3s->h3r);
    h3s->h3r = NULL;
    h3s->type = XQC_H3_STREAM_TYPE_UNKNOWN;

    processed = xqc_h3_stream_process_in(h3s, push_promise,
            sizeof(push_promise), XQC_FALSE);

    CU_ASSERT(processed == -XQC_H3_EPROC_REQUEST);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == H3_FRAME_UNEXPECTED);
    CU_ASSERT(XQC_CONN_ERR_CODE(conn->conn_err) == 0x0105);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
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


/**
 * Test that blocked stream limit uses local settings, not peer's (CVE: CWE-770)
 * RFC 9204 Section 2.1.2: decoder enforces its own SETTINGS_QPACK_BLOCKED_STREAMS
 */
void
xqc_test_h3_blocked_stream_limit_uses_local()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 1024;
    conn->conn_state = XQC_CONN_STATE_ESTABED;

    xqc_h3_conn_t *h3c = xqc_h3_conn_create(conn, NULL);
    CU_ASSERT(h3c != NULL);
    if (h3c == NULL) { xqc_engine_destroy(conn->engine); return; }

    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
            XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    CU_ASSERT(stream != NULL);

    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
            XQC_H3_STREAM_TYPE_REQUEST, NULL);
    CU_ASSERT(h3s != NULL);

    /* Set local limit to 2, peer to UINT64_MAX (simulating attacker) */
    h3c->local_h3_conn_settings.qpack_blocked_streams = 2;
    h3c->peer_h3_conn_settings.qpack_blocked_streams = XQC_H3_SETTINGS_UNSET;  /* UINT64_MAX */

    /* count == 0, local limit == 2: should succeed (count becomes 1) */
    h3c->block_stream_count = 0;
    xqc_h3_blocked_stream_t *bs1 = xqc_h3_conn_add_blocked_stream(h3c, h3s, 1);
    CU_ASSERT(bs1 != NULL);

    /* count == 1, local limit == 2: should succeed (count becomes 2) */
    xqc_h3_blocked_stream_t *bs2 = xqc_h3_conn_add_blocked_stream(h3c, h3s, 2);
    CU_ASSERT(bs2 != NULL);

    /* count == 2, local limit == 2: should be rejected (== limit) */
    xqc_h3_blocked_stream_t *bs3 = xqc_h3_conn_add_blocked_stream(h3c, h3s, 3);
    CU_ASSERT(bs3 == NULL);

    /* Verify peer setting is UINT64_MAX (would have allowed if bug present) */
    CU_ASSERT(h3c->peer_h3_conn_settings.qpack_blocked_streams == XQC_H3_SETTINGS_UNSET);

    /* cleanup: engine_destroy handles full teardown including h3c, h3s, streams */
    xqc_engine_destroy(conn->engine);
}

/*
 * Test that oversized SETTINGS frame is rejected to prevent memory exhaustion.
 * ALIBABA-2026-42073004: xqc_h3_frm_parse_settings must reject frame->len > 1024.
 */
void
xqc_test_h3_settings_frame_size_limit()
{
    xqc_h3_frame_pctx_t pctx;
    ssize_t ret;

    /* Construct a SETTINGS frame with frame->len = 8192 (> 4096 limit)
     * Type: 0x04 (SETTINGS, 1-byte varint)
     * Length: 8192 = 0x2000 (2-byte varint: 0x6000)
     * Payload: 1 byte dummy (just to trigger parsing)
     */
    unsigned char oversized_settings[] = { 0x04, 0x60, 0x00, 0x00 };

    memset(&pctx, 0, sizeof(xqc_h3_frame_pctx_t));
    ret = xqc_h3_frm_parse(oversized_settings, sizeof(oversized_settings), &pctx);
    /* frame parser should return negative error for oversized SETTINGS */
    CU_ASSERT(ret < 0);

    /* Construct a normal-sized SETTINGS frame (len=4, well under 1024 limit)
     * Type: 0x04 (SETTINGS)
     * Length: 4 (1-byte varint: 0x04)
     * Payload: two varint pairs (id=0x06, value=0x00) = 2 bytes each
     */
    unsigned char normal_settings[] = { 0x04, 0x04, 0x06, 0x00, 0x01, 0x00 };

    memset(&pctx, 0, sizeof(xqc_h3_frame_pctx_t));
    ret = xqc_h3_frm_parse(normal_settings, sizeof(normal_settings), &pctx);
    /* normal-sized SETTINGS frame should parse successfully */
    CU_ASSERT(ret >= 0);
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

    /*
     * Drive xqc_h3_request_on_recv_header with fake header data containing
     * an uppercase field name.  This exercises the full error propagation
     * path (helper -> H3_MESSAGE_ERROR -> -XQC_H3_EMALFORMED_HEADER)
     * without touching the sender path or requiring a real wire exchange.
     */
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

    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 16;

    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
                                                       XQC_UNDEFINE_STREAM_ID,
                                                       XQC_CLI_UNI, NULL, NULL);
    CU_ASSERT_FATAL(stream != NULL);

    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
                                                XQC_H3_STREAM_TYPE_CONTROL,
                                                NULL);
    CU_ASSERT_FATAL(h3s != NULL);

    xqc_h3_request_t *h3r = xqc_calloc(1, sizeof(xqc_h3_request_t));
    CU_ASSERT_FATAL(h3r != NULL);
    h3r->h3_stream  = h3s;
    h3r->request_if = &h3c->h3_request_callbacks;
    xqc_init_list_head(&h3r->body_buf);

    xqc_http_header_t fake_hdrs[1];
    fake_hdrs[0].name.iov_base  = (void *)"X-Bad-Name";
    fake_hdrs[0].name.iov_len   = 10;
    fake_hdrs[0].value.iov_base = (void *)"ok";
    fake_hdrs[0].value.iov_len  = 2;
    fake_hdrs[0].flags          = 0;

    xqc_http_headers_t *hdr = &h3r->h3_header[0];
    hdr->headers   = fake_hdrs;
    hdr->count     = 1;
    hdr->total_len = 12;
    hdr->capacity  = 1;

    h3r->completed_header_count = 0;
    h3r->read_flag      = 0;
    xqc_int_t ret = xqc_h3_request_on_recv_header(h3r);
    CU_ASSERT_EQUAL(ret, -XQC_H3_EMALFORMED_HEADER);

    /* all-lowercase header passes the check */
    fake_hdrs[0].name.iov_base = (void *)"x-good-name";
    fake_hdrs[0].name.iov_len  = 11;
    hdr->total_len = 13;
    h3r->completed_header_count = 0;
    h3r->read_flag      = 0;
    ret = xqc_h3_request_on_recv_header(h3r);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    hdr->headers = NULL;
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
    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 9114 Sections 4.2 and 4.1.2: lowercase field names remain valid,
 * while an uppercase field name resets only the malformed request stream.
 * These QPACK literals exercise the request-stream parser and error
 * propagation instead of only testing the byte-scanning helper.
 */
void
xqc_test_h3_lowercase_field_name_stream_accepted()
{
    const unsigned char lowercase[] = {
        0x01, 0x06, 0x00, 0x00, 0x21, 0x78, 0x01, 0x76
    };
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    unsigned char buf[sizeof(lowercase)];
    xqc_memcpy(buf, lowercase, sizeof(buf));

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, buf, sizeof(buf),
                                             XQC_TRUE);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(xqc_h3_stream_get_err(h3s), 0);
    CU_ASSERT_EQUAL(h3s->stream->stream_err, 0);
    CU_ASSERT_EQUAL(conn->conn_err, 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_uppercase_field_name_stream_rejected()
{
    const unsigned char uppercase[] = {
        0x01, 0x06, 0x00, 0x00, 0x21, 0x58, 0x01, 0x76
    };
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    unsigned char buf[sizeof(uppercase)];
    xqc_memcpy(buf, uppercase, sizeof(buf));

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, buf, sizeof(buf),
                                             XQC_TRUE);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(xqc_h3_stream_get_err(h3s), H3_MESSAGE_ERROR);
    CU_ASSERT_EQUAL(h3s->stream->stream_err, H3_MESSAGE_ERROR);
    CU_ASSERT(h3s->stream->stream_state_send
              >= XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT_EQUAL(conn->conn_err, 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


/*
 * RFC 9114 Section 4.3 requires pseudo-header fields to precede regular
 * fields. These field sections contain the same otherwise valid request
 * fields and differ only in the position of :authority relative to x: v.
 */
void
xqc_test_h3_pseudo_header_order_accepted()
{
    const unsigned char pseudo_before_regular[] = {
        0x01, 0x0a, 0x00, 0x00, 0xd1, 0xd7,
        0xc1, 0xc0, 0x21, 0x78, 0x01, 0x76
    };
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    unsigned char buf[sizeof(pseudo_before_regular)];
    xqc_memcpy(buf, pseudo_before_regular, sizeof(buf));

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, buf, sizeof(buf),
                                             XQC_TRUE);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(xqc_h3_stream_get_err(h3s), 0);
    CU_ASSERT_EQUAL(h3s->stream->stream_err, 0);
    CU_ASSERT_EQUAL(conn->conn_err, 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);
    CU_ASSERT_EQUAL(h3s->h3r->completed_header_count, 1);
    CU_ASSERT(h3s->h3r->read_flag & XQC_REQ_NOTIFY_READ_HEADER);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


void
xqc_test_h3_pseudo_header_after_regular_rejected()
{
    const unsigned char pseudo_after_regular[] = {
        0x01, 0x0a, 0x00, 0x00, 0xd1, 0xd7,
        0xc1, 0x21, 0x78, 0x01, 0x76, 0xc0
    };
    xqc_connection_t *conn = NULL;
    xqc_h3_conn_t *h3c = NULL;
    xqc_h3_stream_t *h3s = xqc_h3_msgerr_setup(&conn, &h3c);
    CU_ASSERT_FATAL(h3s != NULL);

    unsigned char buf[sizeof(pseudo_after_regular)];
    xqc_memcpy(buf, pseudo_after_regular, sizeof(buf));

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, buf, sizeof(buf),
                                             XQC_TRUE);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(xqc_h3_stream_get_err(h3s), H3_MESSAGE_ERROR);
    CU_ASSERT_EQUAL(h3s->stream->stream_err, H3_MESSAGE_ERROR);
    CU_ASSERT(h3s->stream->stream_state_send
              >= XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT_EQUAL(conn->conn_err, 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);
    CU_ASSERT_EQUAL(h3s->h3r->completed_header_count, 0);
    CU_ASSERT_EQUAL(h3s->h3r->read_flag, 0);

    xqc_h3_msgerr_teardown(h3s, h3c, conn);
}


/* ======================================================================
 * conn_settings.max_body_buf_per_stream: the HTTP/3 body buffer bound.
 * ====================================================================== */

/* one H3 DATA frame: varint type 0x00, varint length, payload. Lengths here
 * stay under 16384 so the length is a one- or two-byte varint. */
static size_t
xqc_h3_bb_put_data_frame(unsigned char *out, size_t payload_len, unsigned char fill)
{
    size_t n = 0;
    out[n++] = 0x00;                                    /* DATA */
    if (payload_len < 64) {
        out[n++] = (unsigned char)payload_len;
    } else {
        out[n++] = (unsigned char)(0x40 | (payload_len >> 8));
        out[n++] = (unsigned char)(payload_len & 0xff);
    }
    memset(out + n, fill, payload_len);
    return n + payload_len;
}

/* hand `len` bytes to the transport stream as one STREAM frame at *offset,
 * contiguous with what came before so merged_offset_end advances. */
static xqc_int_t
xqc_h3_bb_feed(xqc_connection_t *conn, xqc_stream_t *stream, uint64_t *offset,
    const unsigned char *data, size_t len)
{
    xqc_stream_frame_t *f = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    xqc_int_t ret;

    f->data_offset = *offset;
    f->data_length = len;
    f->data = xqc_malloc(len);
    memcpy(f->data, data, len);

    ret = xqc_insert_stream_frame(conn, stream, f);
    if (ret != XQC_OK) {
        xqc_destroy_stream_frame(f);
        return ret;
    }
    *offset += len;
    return XQC_OK;
}

/* counting wrapper around the real H3 read notify, so a test can tell how
 * many times the engine actually entered the H3 layer. */
static int xqc_h3_bb_notify_count;

static xqc_int_t
xqc_h3_bb_counting_read_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_h3_bb_notify_count++;
    return h3_stream_callbacks.stream_read_notify(stream, user_data);
}

/* non-const: xqc_stream_t::stream_if is a plain pointer */
static xqc_stream_callbacks_t xqc_h3_bb_stream_cbs = {
    .stream_read_notify = xqc_h3_bb_counting_read_notify,
};

typedef struct {
    xqc_connection_t *conn;
    xqc_h3_conn_t    *h3c;
    xqc_h3_stream_t  *h3s;
    xqc_stream_t     *stream;
    uint64_t          offset;       /* next transport stream offset to feed */
} xqc_h3_bb_fixture_t;

/*
 * A client connection carrying one REQUEST stream wired to the real H3
 * callbacks, with both flow-control windows opened wide so the transport
 * reassembly path is never what stops the test.
 */
static xqc_bool_t
xqc_h3_bb_setup_win(xqc_h3_bb_fixture_t *fx, size_t per_stream,
    uint64_t stream_window)
{
    memset(fx, 0, sizeof(*fx));

    fx->conn = test_engine_connect();
    if (fx->conn == NULL) {
        return XQC_FALSE;
    }

    if (fx->conn->alpn) {
        xqc_free(fx->conn->alpn);
    }
    fx->conn->alpn_len = strlen(XQC_ALPN_H3);
    fx->conn->alpn = xqc_calloc(1, fx->conn->alpn_len + 1);
    xqc_memcpy(fx->conn->alpn, XQC_ALPN_H3, fx->conn->alpn_len);

    fx->conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 1024;
    fx->conn->conn_state = XQC_CONN_STATE_ESTABED;

    fx->h3c = xqc_h3_conn_create(fx->conn, NULL);
    if (fx->h3c == NULL) {
        return XQC_FALSE;
    }
    /* xqc_h3_stream_process_data() and _read_notify() both take h3c from
     * here, so it has to be wired as the real ALPN path would wire it. */
    fx->conn->proto_data = fx->h3c;

    /* the setting under test. 0 would mean unbounded. */
    fx->h3c->max_body_buf_per_stream = per_stream;

    fx->stream = xqc_create_stream_with_conn(fx->conn, XQC_UNDEFINE_STREAM_ID,
                                             XQC_CLI_BID, NULL, NULL);
    if (fx->stream == NULL) {
        return XQC_FALSE;
    }
    fx->stream->stream_if = &xqc_h3_bb_stream_cbs;
    fx->stream->stream_flow_ctl.fc_max_stream_data_can_recv = stream_window;
    fx->stream->stream_flow_ctl.fc_stream_recv_window_size = stream_window;
    /* the connection window is never the binding constraint here */
    fx->conn->conn_flow_ctl.fc_max_data_can_recv = 1024ull * 1024 * 1024;

    fx->h3s = xqc_h3_stream_create(fx->h3c, fx->stream,
                                   XQC_H3_STREAM_TYPE_REQUEST, NULL);
    if (fx->h3s == NULL) {
        return XQC_FALSE;
    }
    fx->h3s->h3r = xqc_h3_request_create_inner(fx->h3c, fx->h3s, NULL);
    if (fx->h3s->h3r == NULL) {
        return XQC_FALSE;
    }

    /* this tree rejects DATA before the header section is complete, so the
       fixture presents a request whose headers have been received */
    fx->h3s->h3r->completed_header_count = 1;

    fx->offset = 0;
    xqc_h3_bb_notify_count = 0;
    return XQC_TRUE;
}

/* a window wide enough that flow control never intervenes */
static xqc_bool_t
xqc_h3_bb_setup(xqc_h3_bb_fixture_t *fx, size_t per_stream)
{
    return xqc_h3_bb_setup_win(fx, per_stream, 64ull * 1024 * 1024);
}

/*
 * Attach a second REQUEST stream to an existing fixture's connection, wired
 * exactly as the fixture's own stream is. Returns the h3 stream, or NULL.
 */
static xqc_h3_stream_t *
xqc_h3_bb_add_stream(xqc_h3_bb_fixture_t *fx, xqc_stream_t **out_stream)
{
    xqc_stream_t    *s;
    xqc_h3_stream_t *h3s;

    s = xqc_create_stream_with_conn(fx->conn, XQC_UNDEFINE_STREAM_ID,
                                    XQC_CLI_BID, NULL, NULL);
    if (s == NULL) {
        return NULL;
    }
    s->stream_if = &xqc_h3_bb_stream_cbs;
    s->stream_flow_ctl.fc_max_stream_data_can_recv = 64ull * 1024 * 1024;
    s->stream_flow_ctl.fc_stream_recv_window_size = 64ull * 1024 * 1024;

    h3s = xqc_h3_stream_create(fx->h3c, s, XQC_H3_STREAM_TYPE_REQUEST, NULL);
    if (h3s == NULL) {
        return NULL;
    }
    h3s->h3r = xqc_h3_request_create_inner(fx->h3c, h3s, NULL);
    if (h3s->h3r == NULL) {
        return NULL;
    }

    /* see the note in xqc_h3_bb_setup_win(): DATA on a request that has not
       completed its header section is a frame-sequence error, not a body */
    h3s->h3r->completed_header_count = 1;

    *out_stream = s;
    return h3s;
}

/* feed `frames` DATA frames of `payload` bytes to an arbitrary stream */
static void
xqc_h3_bb_feed_stream(xqc_h3_bb_fixture_t *fx, xqc_stream_t *stream,
    uint64_t *offset, int frames, size_t payload)
{
    unsigned char buf[8192];
    int i;

    for (i = 0; i < frames; i++) {
        size_t n = xqc_h3_bb_put_data_frame(buf, payload,
                                            (unsigned char)('a' + (i % 26)));
        if (xqc_h3_bb_feed(fx->conn, stream, offset, buf, n) != XQC_OK) {
            break;
        }
    }
}

/* drain a request completely, returning the total bytes the application got */
static size_t
xqc_h3_bb_drain_all(xqc_h3_request_t *h3r)
{
    unsigned char sink[64 * 1024];
    size_t total = 0;
    uint8_t fin;
    ssize_t n;

    do {
        fin = 0;
        n = xqc_h3_request_recv_body(h3r, sink, sizeof(sink), &fin);
        if (n > 0) {
            total += (size_t)n;
        }
    } while (n > 0);

    return total;
}

static void
xqc_h3_bb_teardown(xqc_h3_bb_fixture_t *fx)
{
    if (fx->h3s) {
        if (fx->stream) {
            fx->stream->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
        }
        xqc_h3_stream_destroy(fx->h3s);
    }
    if (fx->stream) {
        xqc_destroy_stream(fx->stream);
    }
    if (fx->h3c) {
        xqc_h3_conn_destroy(fx->h3c);
    }
    if (fx->conn) {
        if (fx->conn->alpn) {
            xqc_free(fx->conn->alpn);
            fx->conn->alpn = NULL;
        }
        xqc_engine_destroy(fx->conn->engine);
    }
}

/* feed `frames` DATA frames of `payload` bytes and run one engine read pass */
static void
xqc_h3_bb_feed_and_run(xqc_h3_bb_fixture_t *fx, int frames, size_t payload)
{
    unsigned char buf[8192];
    int i;

    for (i = 0; i < frames; i++) {
        size_t n = xqc_h3_bb_put_data_frame(buf, payload, (unsigned char)('a' + (i % 26)));
        if (xqc_h3_bb_feed(fx->conn, fx->stream, &fx->offset, buf, n) != XQC_OK) {
            break;
        }
    }
    xqc_stream_ready_to_read(fx->stream);
    xqc_process_read_streams(fx->conn);
}


/*
 * The pause de-arms the stream: xqc_stream_shutdown_read() otherwise runs
 * inside xqc_stream_recv(), which the gate skips. Idle engine passes over a
 * paused stream must cost no read notifies; an arrival still does.
 */
void
xqc_test_h3_body_buf_no_spin()
{
    xqc_h3_bb_fixture_t fx;
    int after_pause, after_ticks, i;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);

    /* well past the 8192 B limit: the gate is evaluated at the top of each
       4 KB transport read */
    xqc_h3_bb_feed_and_run(&fx, 40, 3000);

    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    /* the steady state: the request is already over its limit, so the gate
       fires on the first loop iteration with no xqc_stream_recv() call to
       de-arm the stream */
    xqc_stream_ready_to_read(fx.stream);
    xqc_process_read_streams(fx.conn);

    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    /* the de-arm itself, stated directly */
    CU_ASSERT_FALSE(fx.stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ);
    CU_ASSERT(xqc_list_empty(&fx.stream->read_stream_list));

    after_pause = xqc_h3_bb_notify_count;

    /* engine ticks with nothing arriving */
    for (i = 0; i < 50; i++) {
        xqc_process_read_streams(fx.conn);
    }
    after_ticks = xqc_h3_bb_notify_count;

    /* THE ASSERTION: idle ticks cost nothing. */
    CU_ASSERT_EQUAL(after_ticks, after_pause);

    /* the converse, so the assertion above cannot be satisfied by a dead
       stream: one arrival still costs notifies */
    xqc_stream_ready_to_read(fx.stream);
    xqc_process_read_streams(fx.conn);
    CU_ASSERT(xqc_h3_bb_notify_count > after_ticks);
    after_ticks = xqc_h3_bb_notify_count;
    for (i = 0; i < 20; i++) {
        xqc_process_read_streams(fx.conn);
    }
    CU_ASSERT_EQUAL(xqc_h3_bb_notify_count, after_ticks);

    /* and the pause held rather than being an artefact of a closed stream */
    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(fx.conn->conn_state == XQC_CONN_STATE_ESTABED);

    xqc_h3_bb_teardown(&fx);
}


/*
 * XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED collides with none of the stream
 * flags that were already defined.
 */
void
xqc_test_h3_body_buf_flag_bit_is_free()
{
    static const unsigned taken[] = {
        XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED,
        XQC_HTTP3_STREAM_FLAG_FC_BLOCKED,
        XQC_HTTP3_STREAM_FLAG_READ_DATA_BLOCKED,
        XQC_HTTP3_STREAM_FLAG_WRITE_END_STREAM,
        XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED,
        XQC_HTTP3_STREAM_FLAG_READ_EOF,
        XQC_HTTP3_STREAM_FLAG_CLOSED,
        XQC_HTTP3_STREAM_FLAG_PUSH_PROMISE_BLOCKED,
        XQC_HTTP3_STREAM_FLAG_PRIORITY_SET,
        XQC_HTTP3_STREAM_FLAG_RESET,
        XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY,
        XQC_HTTP3_STREAM_IN_READING,
        XQC_HTTP3_STREAM_FLAG_ACTIVELY_CLOSED,
        XQC_HTTP3_STREAM_FLAG_FIN_SENT,
    };
    size_t i;

    for (i = 0; i < sizeof(taken) / sizeof(taken[0]); i++) {
        CU_ASSERT_EQUAL(XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED & taken[i], 0);
    }
    CU_ASSERT_EQUAL(XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED
                    & XQC_HTTP3_STREAM_FLAG_ACTIVELY_CLOSED, 0);
    CU_ASSERT_EQUAL(XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED, 0x4000);

    /* and the body-notify marker is a bit of its own */
    for (i = 0; i < sizeof(taken) / sizeof(taken[0]); i++) {
        CU_ASSERT_EQUAL(XQC_HTTP3_STREAM_FLAG_IN_BODY_NOTIFY & taken[i], 0);
    }
    CU_ASSERT_EQUAL(XQC_HTTP3_STREAM_FLAG_IN_BODY_NOTIFY
                    & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED, 0);
    CU_ASSERT_EQUAL(XQC_HTTP3_STREAM_FLAG_IN_BODY_NOTIFY, 0x8000);
}


/*
 * One paused request does not stop another on the same connection, and the
 * read-stream pass terminates when a stream is re-armed during it.
 */
void
xqc_test_h3_body_buf_second_stream_unaffected()
{
    xqc_h3_bb_fixture_t fx;
    xqc_stream_t *s2;
    xqc_h3_stream_t *h3s2;
    unsigned char frame[8192];
    unsigned char sink[64 * 1024];
    uint64_t off2 = 0, s1_read_point, s2_read_point;
    uint8_t fin = 0;
    int round, before_idle, i;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);

    /* a second request stream on the same connection */
    s2 = xqc_create_stream_with_conn(fx.conn, XQC_UNDEFINE_STREAM_ID,
                                     XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(s2);
    s2->stream_if = &xqc_h3_bb_stream_cbs;
    s2->stream_flow_ctl.fc_max_stream_data_can_recv = 64ull * 1024 * 1024;
    s2->stream_flow_ctl.fc_stream_recv_window_size = 64ull * 1024 * 1024;
    h3s2 = xqc_h3_stream_create(fx.h3c, s2, XQC_H3_STREAM_TYPE_REQUEST, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3s2);
    h3s2->h3r = xqc_h3_request_create_inner(fx.h3c, h3s2, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3s2->h3r);
    /* see the note in xqc_h3_bb_setup_win(): DATA on a request that has not
       completed its header section is a frame-sequence error, not a body */
    h3s2->h3r->completed_header_count = 1;

    /* wedge the first stream: its application never reads */
    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    s1_read_point = fx.stream->stream_data_in.next_read_offset;

    /* the second stream's application behaves: feed, engine pass, drain */
    s2_read_point = s2->stream_data_in.next_read_offset;
    for (round = 0; round < 5; round++) {
        size_t n = xqc_h3_bb_put_data_frame(frame, 3000, 'q');
        CU_ASSERT_EQUAL_FATAL(xqc_h3_bb_feed(fx.conn, s2, &off2, frame, n), XQC_OK);

        /* both streams are on conn_read_streams for this pass: the paused
         * one is re-armed exactly as its own arrivals would re-arm it */
        xqc_stream_ready_to_read(fx.stream);
        xqc_stream_ready_to_read(s2);
        xqc_process_read_streams(fx.conn);

        fin = 0;
        (void)xqc_h3_request_recv_body(h3s2->h3r, sink, sizeof(sink), &fin);

        /* the healthy stream moves every round */
        CU_ASSERT(s2->stream_data_in.next_read_offset > s2_read_point);
        s2_read_point = s2->stream_data_in.next_read_offset;
        /* and is never itself paused */
        CU_ASSERT_FALSE(h3s2->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    }

    /* the wedged stream stayed exactly where it was throughout */
    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_EQUAL(fx.stream->stream_data_in.next_read_offset, s1_read_point);

    /* and with both of them quiet, idle ticks still cost nothing */
    before_idle = xqc_h3_bb_notify_count;
    for (i = 0; i < 20; i++) {
        xqc_process_read_streams(fx.conn);
    }
    CU_ASSERT_EQUAL(xqc_h3_bb_notify_count, before_idle);

    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    s2->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
    xqc_h3_stream_destroy(h3s2);
    xqc_destroy_stream(s2);
    xqc_h3_bb_teardown(&fx);
}


/*
 * The bound itself: while the application does not read, the read point and
 * the advertised limit both stop. The limit is 8192 B and the overshoot
 * allowance is one 4 KB transport read, because the gate is evaluated
 * between reads.
 */
void
xqc_test_h3_body_buf_backpressure()
{
    xqc_h3_bb_fixture_t fx;
    uint64_t read_point_at_pause, fc_at_pause;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);

    /* far more than the limit, never collected by the application */
    xqc_h3_bb_feed_and_run(&fx, 40, 3000);

    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(fx.h3s->h3r->body_buf_bytes <= 8192 + XQC_DATA_BUF_SIZE_4K);
    CU_ASSERT(fx.h3s->h3r->body_buf_bytes >= 8192);

    read_point_at_pause = fx.stream->stream_data_in.next_read_offset;
    fc_at_pause = fx.stream->stream_flow_ctl.fc_max_stream_data_can_recv;

    /* more data arrives and is accepted by the transport; the H3 layer does
     * not touch it, and neither quantity moves */
    xqc_h3_bb_feed_and_run(&fx, 40, 3000);

    CU_ASSERT_EQUAL(fx.stream->stream_data_in.next_read_offset, read_point_at_pause);
    CU_ASSERT_EQUAL(fx.stream->stream_flow_ctl.fc_max_stream_data_can_recv, fc_at_pause);
    CU_ASSERT(fx.h3s->h3r->body_buf_bytes <= 8192 + XQC_DATA_BUF_SIZE_4K);

    /* and the connection is still established, with no error raised */
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);
    CU_ASSERT(fx.conn->conn_state == XQC_CONN_STATE_ESTABED);

    xqc_h3_bb_teardown(&fx);
}


/*
 * The resume: draining below the low watermark clears the flag, re-arms the
 * stream, and the next engine pass moves the read point. Then the same drain
 * against a request whose transport stream is already NULL.
 */
void
xqc_test_h3_body_buf_resume()
{
    xqc_h3_bb_fixture_t fx;
    unsigned char sink[64 * 1024];
    uint8_t fin = 0;
    uint64_t read_point_at_pause, fc_at_pause, prev_read_point;
    ssize_t got;
    int round;

    /* a 128 KiB stream window, small enough for the read point to cross
     * half of it within the test */
    CU_ASSERT_FATAL(xqc_h3_bb_setup_win(&fx, 8192, 128 * 1024) == XQC_TRUE);

    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    read_point_at_pause = fx.stream->stream_data_in.next_read_offset;
    fc_at_pause = fx.stream->stream_flow_ctl.fc_max_stream_data_can_recv;

    /* the application collects everything */
    got = xqc_h3_request_recv_body(fx.h3s->h3r, sink, sizeof(sink), &fin);
    CU_ASSERT(got > 0);
    CU_ASSERT(fx.h3s->h3r->body_buf_bytes
              <= XQC_H3_BODY_BUF_LOW_WATER((size_t)8192));

    /* flag cleared and the stream re-armed */
    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(fx.stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ);

    /* each round is one engine pass and one drain, and each must advance the
     * read point; the loop ends when fc_max_stream_data_can_recv rises */
    prev_read_point = read_point_at_pause;
    for (round = 0; round < 16; round++) {
        xqc_process_read_streams(fx.conn);
        CU_ASSERT(fx.stream->stream_data_in.next_read_offset > prev_read_point);
        prev_read_point = fx.stream->stream_data_in.next_read_offset;

        fin = 0;
        (void)xqc_h3_request_recv_body(fx.h3s->h3r, sink, sizeof(sink), &fin);
        CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

        if (fx.stream->stream_flow_ctl.fc_max_stream_data_can_recv > fc_at_pause) {
            break;
        }
    }
    CU_ASSERT(fx.stream->stream_data_in.next_read_offset > read_point_at_pause);
    CU_ASSERT(fx.stream->stream_flow_ctl.fc_max_stream_data_can_recv > fc_at_pause);

    /* the delayed-destroy shape: xqc_h3_stream_close_notify() nulls
     * h3s->stream and can leave the request alive while its application is
     * still draining */
    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    fx.h3s->stream = NULL;
    fin = 0;
    got = xqc_h3_request_recv_body(fx.h3s->h3r, sink, sizeof(sink), &fin);
    CU_ASSERT(got > 0);
    /* the flag still clears; there is nothing left to re-arm */
    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    fx.h3s->stream = fx.stream;      /* restore for teardown */
    xqc_h3_bb_teardown(&fx);
}


/*
 * RESET_STREAM while paused: the reset still reaches the application, which
 * is why the gate exempts terminal receive states.
 */
void
xqc_test_h3_body_buf_reset_while_paused()
{
    xqc_h3_bb_fixture_t fx;
    int i;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);

    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    /* leave the stream as xqc_process_reset_stream_frame() leaves it:
     * RESET_RECVD, frames_tailq destroyed, counters cleared, re-armed */
    xqc_stream_recv_state_update(fx.stream, XQC_RECV_STREAM_ST_RESET_RECVD);
    xqc_destroy_frame_list(&fx.stream->stream_data_in.frames_tailq);
    fx.stream->stream_data_in.buffered_frame_count = 0;
    fx.stream->stream_data_in.buffered_data_bytes = 0;
    xqc_stream_ready_to_read(fx.stream);
    CU_ASSERT_FATAL(fx.stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ);

    /* one engine pass; the test does not call xqc_stream_recv() itself */
    xqc_process_read_streams(fx.conn);

    /* RESET_RECVD becomes RESET_READ inside xqc_stream_recv(), so RESET_READ
     * is the reset having been delivered */
    CU_ASSERT_EQUAL(fx.stream->stream_state_recv, XQC_RECV_STREAM_ST_RESET_READ);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    /* and nothing further changes it either way */
    for (i = 0; i < 10; i++) {
        xqc_process_read_streams(fx.conn);
    }
    CU_ASSERT_EQUAL(fx.stream->stream_state_recv, XQC_RECV_STREAM_ST_RESET_READ);

    xqc_h3_bb_teardown(&fx);
}


/*
 * Tiny DATA frames: short payloads share a node, so a peer framing DATA at
 * one byte costs a node per XQC_H3_BODY_BUF_MIN_BYTES_PER_NODE bytes, and
 * the byte limit is what stops it. 8192 / 256 = 32 nodes.
 */
void
xqc_test_h3_body_buf_tiny_frames()
{
    xqc_h3_bb_fixture_t fx;
    const uint64_t node_limit = 8192 / XQC_H3_BODY_BUF_MIN_BYTES_PER_NODE;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);

    /* 20,000 one-byte DATA frames: 20,000 bytes of payload against 8,192 */
    xqc_h3_bb_feed_and_run(&fx, 20000, 1);

    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_EQUAL(fx.h3s->h3r->body_buf_bytes, (size_t) 8192);
    CU_ASSERT(fx.h3s->h3r->body_buf_count <= node_limit + 1);

    /* empty DATA frames add no node behind data that notifies anyway */
    xqc_h3_bb_teardown(&fx);
    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    xqc_h3_bb_feed_and_run(&fx, 1, 100);
    xqc_h3_bb_feed_and_run(&fx, 1000, 0);
    CU_ASSERT_EQUAL(fx.h3s->h3r->body_buf_count, 1);
    CU_ASSERT_EQUAL(fx.h3s->h3r->body_buf_bytes, (size_t) 100);

    xqc_h3_bb_teardown(&fx);
}


/*
 * xqc_server_set_conn_settings() copies field by field into
 * engine->default_conn_settings, so the setting has to be named there to
 * reach a server connection.
 */
void
xqc_test_h3_body_buf_reaches_server()
{
    xqc_engine_t *engine = test_create_engine_server();
    xqc_conn_settings_t settings;

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    memset(&settings, 0, sizeof(settings));
    settings.max_body_buf_per_stream = 256 * 1024;
    xqc_server_set_conn_settings(engine, &settings);

    CU_ASSERT_EQUAL(engine->default_conn_settings.max_body_buf_per_stream,
                    (size_t)(256 * 1024));

    /* and zero still means unbounded rather than acquiring a default */
    memset(&settings, 0, sizeof(settings));
    xqc_server_set_conn_settings(engine, &settings);
    CU_ASSERT_EQUAL(engine->default_conn_settings.max_body_buf_per_stream, (size_t)0);

    xqc_engine_destroy(engine);
}


/*
 * Two streams. A request is suspended only while holding at least its own
 * limit, asserted after every engine pass for both streams; a wedged request
 * does not suspend a well-behaved one; and a suspended request resumes on
 * its own drain and then receives every remaining byte.
 */
void
xqc_test_h3_body_buf_conn_arm_orphan()
{
    xqc_h3_bb_fixture_t fx;
    xqc_stream_t *s2 = NULL;
    xqc_h3_stream_t *h3s2;
    uint64_t off2 = 0, s2_read_point;
    size_t got, b_total = 0;
    int i;

    /* per stream, 8 KiB */
    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);

    h3s2 = xqc_h3_bb_add_stream(&fx, &s2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3s2);

    /* A: the slow reader; its application never calls recv_body */
    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(fx.h3s->h3r->body_buf_bytes >= 8192);

    /* (a) B gets a burst it can hold, 5,000 B under its own 8 KiB limit,
     * while A sits wedged at its limit */
    xqc_h3_bb_feed_stream(&fx, s2, &off2, 10, 500);
    xqc_stream_ready_to_read(s2);
    xqc_process_read_streams(fx.conn);

    /* B is not suspended, and it read everything the peer sent it */
    CU_ASSERT_FALSE(h3s2->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_EQUAL(s2->stream_data_in.next_read_offset, off2);
    CU_ASSERT_EQUAL(h3s2->h3r->body_buf_bytes, (size_t)5000);

    got = xqc_h3_bb_drain_all(h3s2->h3r);
    b_total += got;
    CU_ASSERT_EQUAL(got, (size_t)5000);

    /* (b) now give B more than it can hold, so it suspends on its own arm */
    xqc_h3_bb_feed_stream(&fx, s2, &off2, 40, 3000);
    xqc_stream_ready_to_read(s2);
    xqc_process_read_streams(fx.conn);

    CU_ASSERT(h3s2->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    /* never suspended holding nothing */
    CU_ASSERT(h3s2->h3r->body_buf_bytes >= 8192);

    /* B drains and the engine runs, with no further arrivals on either
     * stream and A still wedged: every byte already delivered to B must
     * reach B's application */
    s2_read_point = s2->stream_data_in.next_read_offset;
    for (i = 0; i < 50; i++) {
        b_total += xqc_h3_bb_drain_all(h3s2->h3r);
        xqc_process_read_streams(fx.conn);

        /* the invariant, checked on every pass, for both streams */
        if (h3s2->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED) {
            CU_ASSERT(h3s2->h3r->body_buf_bytes >= 8192);
        }
        if (fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED) {
            CU_ASSERT(fx.h3s->h3r->body_buf_bytes >= 8192);
        }
    }
    b_total += xqc_h3_bb_drain_all(h3s2->h3r);

    CU_ASSERT(s2->stream_data_in.next_read_offset > s2_read_point);
    CU_ASSERT_EQUAL(s2->stream_data_in.next_read_offset, off2);
    CU_ASSERT_EQUAL(b_total, (size_t)(5000 + 40 * 3000));
    CU_ASSERT_FALSE(h3s2->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    /* A is still exactly where it was */
    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    /* and A's own drain still frees A, with every one of A's bytes */
    {
        size_t a_total = 0;
        for (i = 0; i < 100; i++) {
            a_total += xqc_h3_bb_drain_all(fx.h3s->h3r);
            xqc_process_read_streams(fx.conn);
        }
        a_total += xqc_h3_bb_drain_all(fx.h3s->h3r);
        CU_ASSERT_EQUAL(a_total, (size_t)(40 * 3000));
        CU_ASSERT_EQUAL(fx.stream->stream_data_in.next_read_offset, fx.offset);
        CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    }

    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);
    CU_ASSERT(fx.conn->conn_state == XQC_CONN_STATE_ESTABED);

    s2->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
    xqc_h3_stream_destroy(h3s2);
    xqc_destroy_stream(s2);
    xqc_h3_bb_teardown(&fx);
}


/*
 * Nine backlogged requests, each holding its limit and suspended, and a
 * tenth that holds nothing and is still read normally.
 */
void
xqc_test_h3_body_buf_pause_is_per_stream_only()
{
    enum { N = 8 };
    xqc_h3_bb_fixture_t fx;
    xqc_stream_t *s[N];
    xqc_h3_stream_t *h3s[N];
    uint64_t off[N];
    xqc_stream_t *idle_s = NULL;
    xqc_h3_stream_t *idle_h3s;
    uint64_t idle_off = 0;
    size_t held = 0;
    int i;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);

    /* wedge the fixture's own stream plus N more, none of them ever read */
    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    held += fx.h3s->h3r->body_buf_bytes;

    for (i = 0; i < N; i++) {
        off[i] = 0;
        h3s[i] = xqc_h3_bb_add_stream(&fx, &s[i]);
        CU_ASSERT_PTR_NOT_NULL_FATAL(h3s[i]);
        xqc_h3_bb_feed_stream(&fx, s[i], &off[i], 40, 3000);
        xqc_stream_ready_to_read(s[i]);
        xqc_process_read_streams(fx.conn);
        CU_ASSERT(h3s[i]->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
        CU_ASSERT(h3s[i]->h3r->body_buf_bytes >= 8192);
        held += h3s[i]->h3r->body_buf_bytes;
    }

    /* 9 x 8 KiB held across the suspended requests */
    CU_ASSERT(held >= (size_t)(N + 1) * 8192);

    /* the tenth holds nothing */
    idle_h3s = xqc_h3_bb_add_stream(&fx, &idle_s);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idle_h3s);
    xqc_h3_bb_feed_stream(&fx, idle_s, &idle_off, 4, 500);
    xqc_stream_ready_to_read(idle_s);
    xqc_process_read_streams(fx.conn);

    CU_ASSERT_FALSE(idle_h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_EQUAL(idle_s->stream_data_in.next_read_offset, idle_off);
    CU_ASSERT_EQUAL(xqc_h3_bb_drain_all(idle_h3s->h3r), (size_t)2000);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    idle_s->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
    xqc_h3_stream_destroy(idle_h3s);
    xqc_destroy_stream(idle_s);
    for (i = 0; i < N; i++) {
        s[i]->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
        xqc_h3_stream_destroy(h3s[i]);
        xqc_destroy_stream(s[i]);
    }
    xqc_h3_bb_teardown(&fx);
}


/* records the engine timer an application would arm */
static int        xqc_h3_bb_timer_calls;
static xqc_usec_t xqc_h3_bb_timer_last;

static void
xqc_h3_bb_record_timer(xqc_usec_t wake_after, void *user_data)
{
    xqc_h3_bb_timer_calls++;
    xqc_h3_bb_timer_last = wake_after;
}


/*
 * An application that drains from its own event, outside the engine: the
 * resume must arm the engine timer, because a peer waiting for flow-control
 * credit sends nothing that would run the engine otherwise.
 */
void
xqc_test_h3_body_buf_resume_wakes_engine()
{
    xqc_h3_bb_fixture_t    fx;
    xqc_engine_t          *engine;
    xqc_set_event_timer_pt saved;
    uint64_t               read_point;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    engine = fx.conn->engine;

    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    read_point = fx.stream->stream_data_in.next_read_offset;

    saved = engine->eng_callback.set_event_timer;
    engine->eng_callback.set_event_timer = xqc_h3_bb_record_timer;
    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    xqc_h3_bb_timer_calls = 0;
    xqc_h3_bb_timer_last = 0;

    (void)xqc_h3_bb_drain_all(fx.h3s->h3r);

    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(fx.stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ);
    CU_ASSERT_EQUAL(xqc_h3_bb_timer_calls, 1);
    CU_ASSERT_EQUAL(xqc_h3_bb_timer_last, 1);

    /* the pass that timer runs reads the stream again */
    xqc_process_read_streams(fx.conn);
    CU_ASSERT(fx.stream->stream_data_in.next_read_offset > read_point);

    engine->eng_callback.set_event_timer = saved;
    xqc_h3_bb_teardown(&fx);
}


/*
 * The same drain inside the engine arms no timer: the engine is running and
 * reads the queued stream itself. A request whose transport stream is gone
 * has nothing to re-arm, and arms no timer either.
 */
void
xqc_test_h3_body_buf_resume_inside_engine_no_wakeup()
{
    xqc_h3_bb_fixture_t    fx;
    xqc_engine_t          *engine;
    xqc_set_event_timer_pt saved;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    engine = fx.conn->engine;

    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    saved = engine->eng_callback.set_event_timer;
    engine->eng_callback.set_event_timer = xqc_h3_bb_record_timer;
    xqc_h3_bb_timer_calls = 0;

    engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    (void)xqc_h3_bb_drain_all(fx.h3s->h3r);
    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;

    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(fx.stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ);
    CU_ASSERT_EQUAL(xqc_h3_bb_timer_calls, 0);

    /* outside the request's own body notify, the connection is visited
       again: its revisit timer is due now */
    {
        xqc_bool_t is_set = XQC_FALSE;
        xqc_usec_t expire = 0;

        CU_ASSERT_FATAL(fx.h3c->body_buf_revisit_timer >= 0);
        CU_ASSERT_EQUAL(xqc_conn_gp_timer_get_info(fx.conn,
                            fx.h3c->body_buf_revisit_timer, &is_set, &expire),
                        XQC_OK);
        CU_ASSERT(is_set);
        CU_ASSERT(expire <= xqc_monotonic_timestamp());
        xqc_conn_gp_timer_unset(fx.conn, fx.h3c->body_buf_revisit_timer);
    }

    /* inside it, the read notify reads on and nothing is scheduled */
    xqc_process_read_streams(fx.conn);
    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    fx.h3s->flags |= XQC_HTTP3_STREAM_FLAG_IN_BODY_NOTIFY;
    engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    (void)xqc_h3_bb_drain_all(fx.h3s->h3r);
    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    fx.h3s->flags &= ~XQC_HTTP3_STREAM_FLAG_IN_BODY_NOTIFY;
    {
        xqc_bool_t is_set = XQC_TRUE;
        xqc_usec_t expire = 0;

        CU_ASSERT_EQUAL(xqc_conn_gp_timer_get_info(fx.conn,
                            fx.h3c->body_buf_revisit_timer, &is_set, &expire),
                        XQC_OK);
        CU_ASSERT_FALSE(is_set);
    }
    CU_ASSERT_EQUAL(xqc_h3_bb_timer_calls, 0);

    /* paused again, then drained with the transport stream already gone */
    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    fx.h3s->stream = NULL;
    (void)xqc_h3_bb_drain_all(fx.h3s->h3r);
    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_EQUAL(xqc_h3_bb_timer_calls, 0);
    fx.h3s->stream = fx.stream;

    engine->eng_callback.set_event_timer = saved;
    xqc_h3_bb_teardown(&fx);
}


/* an application that collects the whole body inside its read callback */
static size_t xqc_h3_bb_cb_total;

static int
xqc_h3_bb_draining_read_notify(xqc_h3_request_t *h3r,
    xqc_request_notify_flag_t flag, void *user_data)
{
    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        xqc_h3_bb_cb_total += xqc_h3_bb_drain_all(h3r);
    }
    return 0;
}

static xqc_h3_request_callbacks_t xqc_h3_bb_draining_cbs = {
    .h3_request_read_notify = xqc_h3_bb_draining_read_notify,
};


/*
 * A request resumed from its own read callback is read on, inside that same
 * callback: one engine pass over the only readable stream delivers the whole
 * backlog. Without it the pass stops at the first pause, with the resumed
 * stream queued behind a list walk that has already finished.
 */
void
xqc_test_h3_body_buf_resume_from_read_callback()
{
    xqc_h3_bb_fixture_t fx;
    int                 i;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    fx.h3s->h3r->request_if = &xqc_h3_bb_draining_cbs;
    xqc_h3_bb_cb_total = 0;

    /* 120,000 bytes of payload against an 8 KiB limit: one pass */
    xqc_h3_bb_feed_and_run(&fx, 40, 3000);

    CU_ASSERT_EQUAL(xqc_h3_bb_cb_total, (size_t)(40 * 3000));
    CU_ASSERT_EQUAL(fx.stream->stream_data_in.next_read_offset, fx.offset);
    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    /* the loop ends: idle passes cost nothing further */
    for (i = 0; i < 10; i++) {
        xqc_process_read_streams(fx.conn);
    }
    CU_ASSERT_EQUAL(xqc_h3_bb_cb_total, (size_t)(40 * 3000));

    xqc_h3_bb_teardown(&fx);
}


/*
 * A paused request whose peer keeps sending, in small frames, within credit
 * already granted. Each STREAM frame used to cost a reassembly node, so the
 * 8,193rd closed the connection. All are accepted now, and the application
 * still gets every byte, in order, once it drains.
 */
void
xqc_test_h3_body_buf_paused_small_frames()
{
    xqc_h3_bb_fixture_t fx;
    unsigned char       frame[16];
    size_t              total = 0;
    int                 i, refused = 0;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);

    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    /* 20,000 DATA frames of 5 bytes, one STREAM frame each */
    for (i = 0; i < 20000; i++) {
        size_t n = xqc_h3_bb_put_data_frame(frame, 5,
                                            (unsigned char) ('a' + i % 26));
        if (xqc_h3_bb_feed(fx.conn, fx.stream, &fx.offset, frame, n)
            != XQC_OK)
        {
            refused++;
        }
    }

    CU_ASSERT_EQUAL(refused, 0);
    CU_ASSERT(fx.stream->stream_data_in.buffered_frame_count
              < XQC_MAX_STREAM_FRAME_BUFFERED_COUNT);
    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    for (i = 0; i < 1000; i++) {
        total += xqc_h3_bb_drain_all(fx.h3s->h3r);
        if (fx.stream->stream_data_in.next_read_offset == fx.offset
            && xqc_list_empty(&fx.h3s->blocked_buf)
            && xqc_list_empty(&fx.h3s->h3r->body_buf))
        {
            break;
        }
        xqc_process_read_streams(fx.conn);
    }

    CU_ASSERT_EQUAL(total, (size_t) (40 * 3000 + 20000 * 5));
    CU_ASSERT_EQUAL(fx.stream->stream_data_in.next_read_offset, fx.offset);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    xqc_h3_bb_teardown(&fx);
}


/* the peer reports itself blocked on this stream at `limit` */
static xqc_int_t
xqc_h3_bb_stream_data_blocked(xqc_connection_t *conn, xqc_stream_t *stream,
    uint64_t limit)
{
    xqc_packet_in_t pi;
    unsigned char   wire[32];
    unsigned char  *p = wire;

    *p++ = 0x15;
    p = xqc_put_varint(p, stream->stream_id);
    p = xqc_put_varint(p, limit);

    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi.pos = wire;
    pi.last = p;
    return xqc_process_stream_data_blocked_frame(conn, &pi);
}


/*
 * A paused request holds its receive credit: the peer's STREAM_DATA_BLOCKED
 * is answered with nothing while paused, although the read point has moved
 * past the last grant, and with more credit once the application drains.
 */
void
xqc_test_h3_body_buf_pause_holds_credit()
{
    xqc_h3_bb_fixture_t fx;
    uint64_t            fc;

    /* 128 KiB of credit and window: reading ~12 KiB leaves room to grant */
    CU_ASSERT_FATAL(xqc_h3_bb_setup_win(&fx, 8192, 128 * 1024) == XQC_TRUE);

    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(fx.stream->stream_flag & XQC_STREAM_FLAG_RECV_CREDIT_HELD);

    fc = fx.stream->stream_flow_ctl.fc_max_stream_data_can_recv;
    CU_ASSERT_FATAL(fx.stream->stream_data_in.next_read_offset
                    + fx.stream->stream_flow_ctl.fc_stream_recv_window_size
                    > fc);

    CU_ASSERT_EQUAL(xqc_h3_bb_stream_data_blocked(fx.conn, fx.stream, fc),
                    XQC_OK);
    CU_ASSERT_EQUAL(fx.stream->stream_flow_ctl.fc_max_stream_data_can_recv,
                    fc);

    (void)xqc_h3_bb_drain_all(fx.h3s->h3r);
    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_FALSE(fx.stream->stream_flag & XQC_STREAM_FLAG_RECV_CREDIT_HELD);

    CU_ASSERT_EQUAL(xqc_h3_bb_stream_data_blocked(fx.conn, fx.stream, fc),
                    XQC_OK);
    CU_ASSERT(fx.stream->stream_flow_ctl.fc_max_stream_data_can_recv > fc);

    xqc_h3_bb_teardown(&fx);
}


/*
 * The hold is the paused stream's own: a second request on the connection,
 * not paused, is still granted credit when its peer reports it blocked.
 */
void
xqc_test_h3_body_buf_hold_is_per_stream()
{
    xqc_h3_bb_fixture_t fx;
    xqc_stream_t       *s2 = NULL;
    xqc_h3_stream_t    *h3s2;
    uint64_t            off2 = 0, fc2;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    h3s2 = xqc_h3_bb_add_stream(&fx, &s2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3s2);

    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.stream->stream_flag & XQC_STREAM_FLAG_RECV_CREDIT_HELD);

    /* the second request reads 5,000 B and holds nothing back */
    xqc_h3_bb_feed_stream(&fx, s2, &off2, 10, 500);
    xqc_stream_ready_to_read(s2);
    xqc_process_read_streams(fx.conn);
    CU_ASSERT_FALSE(h3s2->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_FALSE(s2->stream_flag & XQC_STREAM_FLAG_RECV_CREDIT_HELD);

    /* a smaller window than its credit, then its peer asks at that credit */
    s2->stream_flow_ctl.fc_max_stream_data_can_recv = 16 * 1024;
    s2->stream_flow_ctl.fc_stream_recv_window_size = 64 * 1024;
    fc2 = s2->stream_flow_ctl.fc_max_stream_data_can_recv;
    CU_ASSERT_EQUAL(xqc_h3_bb_stream_data_blocked(fx.conn, s2, fc2), XQC_OK);
    CU_ASSERT(s2->stream_flow_ctl.fc_max_stream_data_can_recv > fc2);

    /* and the paused one is still held */
    CU_ASSERT(fx.stream->stream_flag & XQC_STREAM_FLAG_RECV_CREDIT_HELD);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    s2->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
    xqc_h3_stream_destroy(h3s2);
    xqc_destroy_stream(s2);
    xqc_h3_bb_teardown(&fx);
}


/* the byte a request body carries at payload position `pos` */
static unsigned char
xqc_h3_bb_pattern(uint64_t pos)
{
    return (unsigned char) (pos * 131 + 17);
}

/* a DATA frame whose payload continues the pattern at *pos (len < 16384) */
static size_t
xqc_h3_bb_put_pattern_frame(unsigned char *out, size_t payload_len,
    uint64_t *pos)
{
    size_t n = 0, i;

    out[n++] = 0x00;
    if (payload_len < 64) {
        out[n++] = (unsigned char) payload_len;

    } else {
        out[n++] = (unsigned char) (0x40 | (payload_len >> 8));
        out[n++] = (unsigned char) (payload_len & 0xff);
    }
    for (i = 0; i < payload_len; i++) {
        out[n++] = xqc_h3_bb_pattern(*pos + i);
    }
    *pos += payload_len;
    return n;
}

/* drain the request, checking each byte against the pattern at *pos */
static int64_t
xqc_h3_bb_drain_verify(xqc_h3_request_t *h3r, uint64_t *pos)
{
    unsigned char sink[16 * 1024];
    int64_t       total = 0;
    uint8_t       fin;
    ssize_t       n, i;

    for ( ;; ) {
        fin = 0;
        n = xqc_h3_request_recv_body(h3r, sink, sizeof(sink), &fin);
        if (n <= 0) {
            break;
        }
        for (i = 0; i < n; i++) {
            if (sink[i] != xqc_h3_bb_pattern(*pos + i)) {
                return -1;
            }
        }
        *pos += n;
        total += n;
    }
    return total;
}

/* input the H3 layer read and kept, as a QPACK-blocked request keeps it */
static void
xqc_h3_bb_keep_input(xqc_h3_bb_fixture_t *fx, const unsigned char *data,
    size_t len, uint8_t fin)
{
    xqc_var_buf_t *buf = xqc_var_buf_create(len);

    CU_ASSERT_PTR_NOT_NULL_FATAL(buf);
    CU_ASSERT_EQUAL_FATAL(xqc_var_buf_save_data(buf, data, len), XQC_OK);
    buf->fin_flag = fin;
    CU_ASSERT_EQUAL_FATAL(xqc_list_buf_to_tail(&fx->h3s->blocked_buf, buf),
                          XQC_OK);
    fx->h3s->blocked_buf_size += len;
    fx->h3c->total_blocked_buf_size += len;
}

/* keep 50 DATA frames of 1,000 bytes and 3,000 of one byte */
static uint64_t
xqc_h3_bb_keep_backlog(xqc_h3_bb_fixture_t *fx, uint8_t fin)
{
    unsigned char frame[1100];
    uint64_t      pos = 0;
    size_t        n;
    int           i;

    for (i = 0; i < 50; i++) {
        n = xqc_h3_bb_put_pattern_frame(frame, 1000, &pos);
        xqc_h3_bb_keep_input(fx, frame, n, 0);
    }
    for (i = 0; i < 3000; i++) {
        n = xqc_h3_bb_put_pattern_frame(frame, 1, &pos);
        xqc_h3_bb_keep_input(fx, frame, n, fin && i == 2999);
    }
    return pos;
}


/*
 * The limit holds where DATA is appended: a read that crosses it stops
 * there, the rest of the read is kept, and it is delivered, in order,
 * before anything the transport stream received later.
 */
void
xqc_test_h3_body_buf_limit_is_exact()
{
    xqc_h3_bb_fixture_t fx;
    unsigned char       frame[4200];
    uint64_t            fed = 0, got = 0;
    int64_t             n;
    int                 i;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);

    for (i = 0; i < 5; i++) {
        size_t len = xqc_h3_bb_put_pattern_frame(frame, 4000, &fed);
        CU_ASSERT_EQUAL_FATAL(xqc_h3_bb_feed(fx.conn, fx.stream, &fx.offset,
                                             frame, len), XQC_OK);
    }
    xqc_stream_ready_to_read(fx.stream);
    xqc_process_read_streams(fx.conn);

    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_EQUAL(fx.h3s->h3r->body_buf_bytes, (size_t) 8192);
    CU_ASSERT(fx.h3s->blocked_buf_size > 0);
    CU_ASSERT(fx.h3s->blocked_buf_size <= XQC_DATA_BUF_SIZE_4K);

    /* more arrives behind the kept input */
    for (i = 0; i < 5; i++) {
        size_t len = xqc_h3_bb_put_pattern_frame(frame, 4000, &fed);
        CU_ASSERT_EQUAL_FATAL(xqc_h3_bb_feed(fx.conn, fx.stream, &fx.offset,
                                             frame, len), XQC_OK);
    }

    for (i = 0; i < 100 && got < fed; i++) {
        n = xqc_h3_bb_drain_verify(fx.h3s->h3r, &got);
        CU_ASSERT_FATAL(n >= 0);
        CU_ASSERT(fx.h3s->h3r->body_buf_bytes <= 8192);
        xqc_process_read_streams(fx.conn);
    }
    CU_ASSERT_EQUAL(got, fed);
    CU_ASSERT(xqc_list_empty(&fx.h3s->blocked_buf));
    CU_ASSERT_EQUAL(fx.h3c->total_blocked_buf_size, 0);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    xqc_h3_bb_teardown(&fx);
}


/*
 * The replay of input kept while a request waited on QPACK obeys the limit
 * in bytes and in nodes, keeps the rest, and still delivers every byte in
 * order as the application drains.
 */
void
xqc_test_h3_body_buf_replay_is_bounded()
{
    xqc_h3_bb_fixture_t fx;
    uint64_t            kept, got = 0;
    int64_t             n;
    int                 i;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    kept = xqc_h3_bb_keep_backlog(&fx, 0);

    CU_ASSERT_EQUAL(xqc_h3_stream_process_blocked_stream(fx.h3s), XQC_OK);

    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(fx.stream->stream_flag & XQC_STREAM_FLAG_RECV_CREDIT_HELD);
    CU_ASSERT(fx.h3s->h3r->body_buf_bytes <= 8192);
    CU_ASSERT(fx.h3s->h3r->body_buf_count
              <= 8192 / XQC_H3_BODY_BUF_MIN_BYTES_PER_NODE + 1);
    CU_ASSERT_FALSE(xqc_list_empty(&fx.h3s->blocked_buf));

    for (i = 0; i < 1000 && got < kept; i++) {
        n = xqc_h3_bb_drain_verify(fx.h3s->h3r, &got);
        CU_ASSERT_FATAL(n >= 0);
        CU_ASSERT(fx.h3s->h3r->body_buf_count
                  <= 8192 / XQC_H3_BODY_BUF_MIN_BYTES_PER_NODE + 1);
        xqc_process_read_streams(fx.conn);
    }
    CU_ASSERT_EQUAL(got, kept);
    CU_ASSERT(xqc_list_empty(&fx.h3s->blocked_buf));
    CU_ASSERT_EQUAL(fx.h3s->blocked_buf_size, 0);
    CU_ASSERT_EQUAL(fx.h3c->total_blocked_buf_size, 0);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    xqc_h3_bb_teardown(&fx);
}


/*
 * Once the peer's FIN has been read, the replay runs to the end: the rest
 * of the request is already in memory, and a transport stream that has
 * delivered everything may close and drop whatever was held back.
 */
void
xqc_test_h3_body_buf_replay_after_fin()
{
    xqc_h3_bb_fixture_t fx;
    unsigned char       sink[64 * 1024];
    uint64_t            kept, got = 0;
    uint8_t             fin = 0;
    ssize_t             n;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    kept = xqc_h3_bb_keep_backlog(&fx, 1);
    fx.h3s->flags |= XQC_HTTP3_STREAM_FLAG_READ_EOF;

    CU_ASSERT_EQUAL(xqc_h3_stream_process_blocked_stream(fx.h3s), XQC_OK);

    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(xqc_list_empty(&fx.h3s->blocked_buf));
    CU_ASSERT_EQUAL(fx.h3s->h3r->body_buf_bytes, (size_t) kept);
    CU_ASSERT(fx.h3s->h3r->fin_flag);

    do {
        n = xqc_h3_request_recv_body(fx.h3s->h3r, sink, sizeof(sink), &fin);
        if (n > 0) {
            got += n;
        }
    } while (n > 0 && !fin);
    CU_ASSERT_EQUAL(got, kept);
    CU_ASSERT(fin);

    xqc_h3_bb_teardown(&fx);
}


/* keep input on an arbitrary request stream, as a QPACK-blocked one would */
static void
xqc_h3_bb_keep_input_on(xqc_h3_stream_t *h3s, const unsigned char *data,
    size_t len)
{
    xqc_var_buf_t *buf = xqc_var_buf_create(len);

    CU_ASSERT_PTR_NOT_NULL_FATAL(buf);
    CU_ASSERT_EQUAL_FATAL(xqc_var_buf_save_data(buf, data, len), XQC_OK);
    CU_ASSERT_EQUAL_FATAL(xqc_list_buf_to_tail(&h3s->blocked_buf, buf),
                          XQC_OK);
    h3s->blocked_buf_size += len;
    h3s->h3c->total_blocked_buf_size += len;
}

/* the stream whose QPACK unblock the next body notify stands in for */
static xqc_h3_stream_t *xqc_h3_bb_unblock_target;

static int
xqc_h3_bb_unblocking_read_notify(xqc_h3_request_t *h3r,
    xqc_request_notify_flag_t flag, void *user_data)
{
    xqc_h3_stream_t *target = xqc_h3_bb_unblock_target;

    /* once: replay the target as the encoder stream's inserts would */
    xqc_h3_bb_unblock_target = NULL;
    if (target != NULL) {
        CU_ASSERT_EQUAL(xqc_h3_stream_process_blocked_stream(target), XQC_OK);
    }
    return 0;
}

static xqc_h3_request_callbacks_t xqc_h3_bb_unblocking_cbs = {
    .h3_request_read_notify = xqc_h3_bb_unblocking_read_notify,
};


/*
 * A request paused by a replay that runs from another stream's processing,
 * as a QPACK unblock does from the encoder stream's, while the connection's
 * read-list walk holds the paused stream as its next entry. The walk must
 * survive, and the paused request must still deliver every byte in order.
 */
void
xqc_test_h3_body_buf_pause_during_read_walk()
{
    xqc_h3_bb_fixture_t fx;
    xqc_stream_t       *s2 = NULL;
    xqc_h3_stream_t    *h3s2;
    unsigned char       frame[1100];
    uint64_t            kept = 0, total, got = 0, off2 = 0;
    size_t              n;
    int64_t             r;
    int                 i;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    h3s2 = xqc_h3_bb_add_stream(&fx, &s2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3s2);

    /* 40,000 bytes kept on the second request, past its 8 KiB limit */
    for (i = 0; i < 40; i++) {
        n = xqc_h3_bb_put_pattern_frame(frame, 1000, &kept);
        xqc_h3_bb_keep_input_on(h3s2, frame, n);
    }

    /* one frame each, so both streams are on the read list, first first;
       the second request's continues its body after the kept bytes */
    n = xqc_h3_bb_put_data_frame(frame, 10, 'x');
    CU_ASSERT_EQUAL_FATAL(xqc_h3_bb_feed(fx.conn, fx.stream, &fx.offset,
                                         frame, n), XQC_OK);
    total = kept;
    n = xqc_h3_bb_put_pattern_frame(frame, 10, &total);
    CU_ASSERT_EQUAL_FATAL(xqc_h3_bb_feed(fx.conn, s2, &off2, frame, n),
                          XQC_OK);
    xqc_stream_ready_to_read(fx.stream);
    xqc_stream_ready_to_read(s2);

    fx.h3s->h3r->request_if = &xqc_h3_bb_unblocking_cbs;
    xqc_h3_bb_unblock_target = h3s2;
    xqc_process_read_streams(fx.conn);

    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);
    CU_ASSERT(h3s2->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(h3s2->h3r->body_buf_bytes <= 8192);

    /* the kept bytes first, then the frame from the transport stream */
    for (i = 0; i < 100 && got < total; i++) {
        r = xqc_h3_bb_drain_verify(h3s2->h3r, &got);
        CU_ASSERT_FATAL(r >= 0);
        xqc_process_read_streams(fx.conn);
    }
    CU_ASSERT_EQUAL(got, total);
    CU_ASSERT(xqc_list_empty(&h3s2->blocked_buf));
    CU_ASSERT_EQUAL(fx.h3c->total_blocked_buf_size, 0);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    s2->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
    xqc_h3_stream_destroy(h3s2);
    xqc_destroy_stream(s2);
    xqc_h3_bb_teardown(&fx);
}


/* the peer has sent everything, and its FIN, on the fixture's stream */
static void
xqc_h3_bb_peer_finished(xqc_h3_bb_fixture_t *fx)
{
    fx->stream->stream_data_in.stream_determined = XQC_TRUE;
    fx->stream->stream_data_in.stream_length = fx->offset;
    fx->stream->stream_max_recv_offset = fx->offset;
    xqc_stream_recv_state_update(fx->stream, XQC_RECV_STREAM_ST_SIZE_KNOWN);
    xqc_stream_recv_state_update(fx->stream, XQC_RECV_STREAM_ST_DATA_RECVD);
}


/*
 * An application that closes a paused request collects nothing more. The
 * request stops holding its input, so its transport stream reads to the
 * end and can finish; left paused, it would stay open for good once the
 * peer had sent everything, since no STOP_SENDING goes out then.
 */
void
xqc_test_h3_body_buf_close_releases_pause()
{
    xqc_h3_bb_fixture_t fx;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    fx.conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;

    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    xqc_h3_bb_peer_finished(&fx);

    /* the close runs the connection itself, outside the engine */
    CU_ASSERT_EQUAL(xqc_h3_request_close(fx.h3s->h3r), XQC_OK);
    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_FALSE(fx.stream->stream_flag & XQC_STREAM_FLAG_RECV_CREDIT_HELD);

    xqc_process_read_streams(fx.conn);
    CU_ASSERT_EQUAL(fx.stream->stream_data_in.next_read_offset, fx.offset);
    CU_ASSERT_EQUAL(fx.stream->stream_state_recv,
                    XQC_RECV_STREAM_ST_DATA_READ);
    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    xqc_h3_bb_teardown(&fx);
}


/*
 * A reset of a request whose read stopped at its limit: the rest of the
 * read it kept is dropped, not replayed into a body nobody will collect,
 * and the reset still reaches the application.
 */
void
xqc_test_h3_body_buf_reset_drops_kept_input()
{
    xqc_h3_bb_fixture_t fx;
    unsigned char       frame[4200];
    uint64_t            fed = 0;
    size_t              held;
    int                 i;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    for (i = 0; i < 5; i++) {
        size_t len = xqc_h3_bb_put_pattern_frame(frame, 4000, &fed);
        CU_ASSERT_EQUAL_FATAL(xqc_h3_bb_feed(fx.conn, fx.stream, &fx.offset,
                                             frame, len), XQC_OK);
    }
    xqc_stream_ready_to_read(fx.stream);
    xqc_process_read_streams(fx.conn);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_FATAL(!xqc_list_empty(&fx.h3s->blocked_buf));
    held = fx.h3s->h3r->body_buf_bytes;

    xqc_stream_recv_state_update(fx.stream, XQC_RECV_STREAM_ST_RESET_RECVD);
    xqc_destroy_frame_list(&fx.stream->stream_data_in.frames_tailq);
    fx.stream->stream_data_in.buffered_frame_count = 0;
    xqc_stream_ready_to_read(fx.stream);
    xqc_process_read_streams(fx.conn);

    CU_ASSERT(xqc_list_empty(&fx.h3s->blocked_buf));
    CU_ASSERT_EQUAL(fx.h3s->blocked_buf_size, 0);
    CU_ASSERT_EQUAL(fx.h3c->total_blocked_buf_size, 0);
    CU_ASSERT_EQUAL(fx.h3s->h3r->body_buf_bytes, held);
    CU_ASSERT_EQUAL(fx.stream->stream_state_recv,
                    XQC_RECV_STREAM_ST_RESET_READ);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    xqc_h3_bb_teardown(&fx);
}


/*
 * A body that ends with an empty DATA frame and the FIN still notifies the
 * application, which then sees the FIN: an empty payload still makes a node
 * when body_buf is otherwise empty.
 */
void
xqc_test_h3_body_buf_empty_data_fin_notifies()
{
    xqc_h3_bb_fixture_t fx;
    unsigned char       sink[16];
    uint8_t             fin = 0;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);

    xqc_h3_bb_feed_and_run(&fx, 1, 0);
    xqc_h3_bb_peer_finished(&fx);
    xqc_stream_ready_to_read(fx.stream);
    xqc_process_read_streams(fx.conn);

    CU_ASSERT_FALSE(xqc_list_empty(&fx.h3s->h3r->body_buf));
    CU_ASSERT(fx.h3s->h3r->read_flag & XQC_REQ_NOTIFY_READ_BODY);
    CU_ASSERT_EQUAL(xqc_h3_request_recv_body(fx.h3s->h3r, sink, sizeof(sink),
                                             &fin), 0);
    CU_ASSERT(fin);

    xqc_h3_bb_teardown(&fx);
}


/*
 * A pause lasts only while nothing is read. An arrival that finds the
 * request below its limit, though above the low watermark, reads on, and
 * the pause and the credit hold end with it. After the peer's FIN a resume
 * releases the hold without re-arming a stream with nothing left to read.
 */
void
xqc_test_h3_body_buf_stale_pause_ends()
{
    xqc_h3_bb_fixture_t fx;
    unsigned char       frame[4200], sink[4096];
    uint64_t            fed = 0;
    uint8_t             fin = 0;
    int                 i;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    for (i = 0; i < 3; i++) {
        size_t len = xqc_h3_bb_put_pattern_frame(frame, 3000, &fed);
        CU_ASSERT_EQUAL_FATAL(xqc_h3_bb_feed(fx.conn, fx.stream, &fx.offset,
                                             frame, len), XQC_OK);
    }
    xqc_stream_ready_to_read(fx.stream);
    xqc_process_read_streams(fx.conn);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    /* collect 4 KiB: below the limit, above its quarter */
    CU_ASSERT_EQUAL(xqc_h3_request_recv_body(fx.h3s->h3r, sink, sizeof(sink),
                                             &fin), (ssize_t) sizeof(sink));
    CU_ASSERT(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    /* an arrival: the request reads on */
    xqc_h3_bb_feed_and_run(&fx, 1, 100);
    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_FALSE(fx.stream->stream_flag & XQC_STREAM_FLAG_RECV_CREDIT_HELD);
    CU_ASSERT(xqc_list_empty(&fx.h3s->blocked_buf));

    /* after the FIN, a resume re-arms nothing */
    fx.h3s->flags |= XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED
                     | XQC_HTTP3_STREAM_FLAG_READ_EOF;
    xqc_stream_hold_recv_credit(fx.stream, XQC_TRUE);
    xqc_stream_shutdown_read(fx.stream);
    xqc_h3_stream_body_buf_resume(fx.h3s);
    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_FALSE(fx.stream->stream_flag & XQC_STREAM_FLAG_RECV_CREDIT_HELD);
    CU_ASSERT_FALSE(fx.stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ);

    xqc_h3_bb_teardown(&fx);
}


/* whether `conn` is in the engine's active queue, found by address alone */
static xqc_bool_t
xqc_h3_bb_in_active_queue(xqc_engine_t *engine, xqc_connection_t *conn)
{
    xqc_pq_t            *pq = engine->conns_active_pq;
    xqc_conns_pq_elem_t *el;
    size_t               i;

    for (i = 0; i < pq->count; i++) {
        el = (xqc_conns_pq_elem_t *) (pq->elements + i * pq->element_size);
        if (el->conn == conn) {
            return XQC_TRUE;
        }
    }
    return XQC_FALSE;
}


/*
 * A request drained on a connection that is closing resumes, but the
 * connection is not queued again: it reads nothing more.
 */
void
xqc_test_h3_body_buf_resume_closing_conn()
{
    xqc_h3_bb_fixture_t fx;
    xqc_engine_t       *engine;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    engine = fx.conn->engine;

    xqc_h3_bb_feed_and_run(&fx, 40, 3000);
    CU_ASSERT_FATAL(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    xqc_engine_remove_wakeup_queue(engine, fx.conn);
    xqc_engine_remove_active_queue(engine, fx.conn);
    fx.conn->conn_state = XQC_CONN_STATE_CLOSING;

    (void) xqc_h3_bb_drain_all(fx.h3s->h3r);
    CU_ASSERT_FALSE(fx.h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT_FALSE(fx.stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ);
    CU_ASSERT_FALSE(xqc_h3_bb_in_active_queue(engine, fx.conn));

    fx.conn->conn_state = XQC_CONN_STATE_ESTABED;
    xqc_h3_bb_teardown(&fx);
}


/* when the first request closes, it closes or drains the other one */
static xqc_h3_request_t *xqc_h3_bb_first;
static xqc_h3_request_t *xqc_h3_bb_sibling;
static int               xqc_h3_bb_sibling_drains;

static int
xqc_h3_bb_sibling_close_notify(xqc_h3_request_t *h3r, void *user_data)
{
    unsigned char sink[4096];
    uint8_t       fin;
    ssize_t       n;

    if (h3r != xqc_h3_bb_first || xqc_h3_bb_sibling == NULL) {
        return 0;
    }

    if (!xqc_h3_bb_sibling_drains) {
        xqc_h3_request_close(xqc_h3_bb_sibling);
        return 0;
    }

    do {
        fin = 0;
        n = xqc_h3_request_recv_body(xqc_h3_bb_sibling, sink, sizeof(sink),
                                     &fin);
    } while (n > 0);
    return 0;
}

static xqc_h3_request_callbacks_t xqc_h3_bb_sibling_cbs = {
    .h3_request_close_notify = xqc_h3_bb_sibling_close_notify,
};

static void
xqc_h3_bb_teardown_resumes_sibling(xqc_bool_t drains)
{
    xqc_h3_bb_fixture_t fx;
    xqc_engine_t       *engine;
    xqc_connection_t   *dead;
    xqc_h3_stream_t    *h3s_b;
    xqc_stream_t       *stream_b = NULL;
    uint64_t            off_b = 0;

    CU_ASSERT_FATAL(xqc_h3_bb_setup(&fx, 8192) == XQC_TRUE);
    engine = fx.conn->engine;
    h3s_b = xqc_h3_bb_add_stream(&fx, &stream_b);
    CU_ASSERT_PTR_NOT_NULL_FATAL(h3s_b);

    /* both streams close through the real HTTP/3 callbacks */
    fx.stream->stream_if = (xqc_stream_callbacks_t *) &h3_stream_callbacks;
    stream_b->stream_if = (xqc_stream_callbacks_t *) &h3_stream_callbacks;
    fx.h3s->h3r->request_if = &xqc_h3_bb_sibling_cbs;
    h3s_b->h3r->request_if = &xqc_h3_bb_sibling_cbs;
    xqc_h3_bb_first = fx.h3s->h3r;
    xqc_h3_bb_sibling = h3s_b->h3r;
    xqc_h3_bb_sibling_drains = drains;

    xqc_h3_bb_feed_stream(&fx, stream_b, &off_b, 40, 3000);
    xqc_stream_ready_to_read(stream_b);
    xqc_process_read_streams(fx.conn);
    CU_ASSERT_FATAL(h3s_b->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    /* the connection's close reaches the HTTP/3 layer, as ALPN wires it */
    fx.conn->app_proto_cbs.conn_cbs = h3_conn_callbacks;
    fx.conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;

    /* destroyed the way xqc_engine_main_logic() destroys a closed one */
    xqc_engine_remove_wakeup_queue(engine, fx.conn);
    xqc_engine_remove_active_queue(engine, fx.conn);
    fx.conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
    fx.conn->conn_state = XQC_CONN_STATE_CLOSED;
    dead = fx.conn;
    xqc_conn_destroy(fx.conn);

    /* if it were queued, the engine would read the freed connection */
    CU_ASSERT_FALSE_FATAL(xqc_h3_bb_in_active_queue(engine, dead));

    xqc_h3_bb_first = NULL;
    xqc_h3_bb_sibling = NULL;
    xqc_engine_destroy(engine);
}

/*
 * A request's close notify, run while xqc_conn_destroy() frees the
 * connection, closes or drains a paused request on the same connection.
 * The freed connection is not left in the engine's active queue.
 */
void
xqc_test_h3_body_buf_resume_in_conn_teardown()
{
    xqc_h3_bb_teardown_resumes_sibling(XQC_FALSE);
    xqc_h3_bb_teardown_resumes_sibling(XQC_TRUE);
}
