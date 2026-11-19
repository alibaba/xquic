/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <arpa/inet.h>
#include "xqc_qpack_test.h"
#include "src/http3/xqc_h3_header.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/qpack/xqc_qpack.h"
#include "src/common/xqc_time.h"
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>

#include "tests/unittest/xqc_common_test.h"
#include "tests/unittest/xqc_alloc_wrap.h"

#define XQC_TEST_ENCODER_MAX_HEADERS 128

typedef struct xqc_ins_buf_s {
    xqc_var_buf_t *enc_ins;
    xqc_var_buf_t *dec_ins;
} xqc_ins_buf_t;


xqc_var_buf_t *
xqc_qpk_test_get_ins_buf(xqc_qpack_ins_type_t type, void *user_data)
{
    xqc_ins_buf_t *ins_buf = ((xqc_ins_buf_t *)user_data);
    if (type == XQC_INS_TYPE_ENCODER) {
        return ins_buf->enc_ins;
    } else {
        return ins_buf->dec_ins;
    }
}

ssize_t 
xqc_qpk_test_write_ins(xqc_qpack_ins_type_t type, xqc_var_buf_t *buf,
    void *user_data)
{
    return buf->data_len;
}

xqc_qpack_ins_cb_t ins_cb = {
    xqc_qpk_test_get_ins_buf,
    xqc_qpk_test_write_ins
};

void
xqc_qpack_test_basic()
{
    xqc_int_t ret = XQC_OK;
    xqc_var_buf_t *efs_buf_client = xqc_var_buf_create(32*1024);
    xqc_var_buf_t *enc_ins_buf_client = xqc_var_buf_create(16384);
    xqc_var_buf_t *dec_ins_buf_client = xqc_var_buf_create(16384);
    xqc_ins_buf_t ins_buf_client = {enc_ins_buf_client, dec_ins_buf_client};

    xqc_var_buf_t *efs_buf_server = xqc_var_buf_create(32*1024);
    xqc_var_buf_t *enc_ins_buf_server = xqc_var_buf_create(16384);
    xqc_var_buf_t *dec_ins_buf_server = xqc_var_buf_create(16384);
    xqc_ins_buf_t ins_buf_server = {enc_ins_buf_server, dec_ins_buf_server};
    xqc_bool_t blocked = XQC_FALSE;

    xqc_http_header_t header_in[XQC_TEST_ENCODER_MAX_HEADERS] = {
        {
            .name   = {.iov_base = ":method", .iov_len = 7},
            .value  = {.iov_base = "POST", .iov_len = 4},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "host", .iov_len = 4},
            .value  = {.iov_base = "test.xquic.com.cn", .iov_len = 17},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "host", .iov_len = 4},
            .value  = {.iov_base = "www.xquic.com.cn", .iov_len = 17},  /* Insert With Name Reference in dtable */
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "never_idx_hdr", .iov_len = 13},
            .value  = {.iov_base = "never_idx_hdr_value", .iov_len = 19},
            .flags  = XQC_HTTP_HEADER_FLAG_NEVER_INDEX
        },
        {
            .name   = {.iov_base = "never_idx_value_hdr", .iov_len = 19},
            .value  = {.iov_base = "never_idx_value_hdr_value", .iov_len = 25},
            .flags  = XQC_HTTP_HEADER_FLAG_NEVER_INDEX_VALUE
        },
        {
            .name   = {.iov_base = "cookie", .iov_len = 6},
            .value  = {.iov_base = "this_is_a_cookie_buf_pretending_to_be_long", .iov_len = 42},  /* Insert With Name Reference in stable */
        },
        {
            .name   = {.iov_base = "cookie", .iov_len = 6},
            .value  = {.iov_base = "this_is_a_cookie_buf_pretending_to_be_long", .iov_len = 2500},  /* fake length, Insert With Name Reference in stable */
        },
        {
            .name   = {.iov_base = "cookie", .iov_len = 6},
            .value  = {.iov_base = "short_cookie", .iov_len = 12},
        },
        {
            .name   = {.iov_base = ":authority", .iov_len = 10},
            .value  = {.iov_base = "authority_value", .iov_len = 15},   /* fake length */
        },
    };
    xqc_http_headers_t hdrs_in = {
        header_in, 6, XQC_TEST_ENCODER_MAX_HEADERS
    };


    xqc_http_header_t header_in2[XQC_TEST_ENCODER_MAX_HEADERS] = {
        {
            .name   = {.iov_base = ":method", .iov_len = 7},
            .value  = {.iov_base = "POST", .iov_len = 4},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "test_blocked_encoder", .iov_len = 20},
            .value  = {.iov_base = "test_blocked_encoder", .iov_len = 20},  /* fake length */
            .flags  = 0
        }
    };
    xqc_http_headers_t hdrs_in2 = {
        header_in2, 2, XQC_TEST_ENCODER_MAX_HEADERS
    };


    xqc_http_headers_t hdrs_out;
    xqc_h3_headers_create_buf(&hdrs_out, XQC_TEST_ENCODER_MAX_HEADERS);

    xqc_http_headers_t hdrs_out2;
    xqc_h3_headers_create_buf(&hdrs_out2, XQC_TEST_ENCODER_MAX_HEADERS);

    ssize_t read = 0;
    size_t recvd = 0;

    /* encoder side */
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);

    xqc_qpack_t *qpk_client = xqc_qpack_create(16384, 16384, engine->log, &ins_cb, &ins_buf_client);
    CU_ASSERT(qpk_client != NULL);

    ret = xqc_qpack_set_enc_max_dtable_cap(qpk_client, 16 * 1024);
    CU_ASSERT(ret == XQC_OK);
    xqc_qpack_set_enc_insert_limit(qpk_client, 0.25, 0.75);
    /* set encoder's blocked streams, pretending it as SETTINGS from decoder */
    ret = xqc_qpack_set_max_blocked_stream(qpk_client, 1);
    CU_ASSERT(ret == XQC_OK);
    /* set encoder's dtable cap. pretending it as SETTINGS from decoder, and set dtable cap ins generated */
    ret = xqc_qpack_set_dtable_cap(qpk_client, 16384);
    CU_ASSERT(ret == XQC_OK && enc_ins_buf_client->data_len > 0);


    /* decoder side */
    xqc_qpack_t *qpk_server = xqc_qpack_create(16384, 16384, engine->log, &ins_cb, &ins_buf_server);

    CU_ASSERT(qpk_server != NULL);
    ret = xqc_qpack_set_enc_max_dtable_cap(qpk_server, 16 * 1024);
    CU_ASSERT(ret == XQC_OK);
    xqc_qpack_set_enc_insert_limit(qpk_server, 0.25, 0.75);
    ret = xqc_qpack_set_max_blocked_stream(qpk_server, 1);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_qpack_set_dtable_cap(qpk_server, 16384);
    CU_ASSERT(ret == XQC_OK && enc_ins_buf_server->data_len > 0);


    /* server received Set Dynamic Table Capacity from client */
    read = xqc_qpack_process_encoder(qpk_server, enc_ins_buf_client->data, enc_ins_buf_client->data_len);
    CU_ASSERT(read == enc_ins_buf_client->data_len);
    xqc_var_buf_clear(enc_ins_buf_client);

    /* client received Set Dynamic Table Capacity from server */
    read = xqc_qpack_process_encoder(qpk_client, enc_ins_buf_server->data, enc_ins_buf_server->data_len);
    CU_ASSERT(read == enc_ins_buf_server->data_len);
    xqc_var_buf_clear(enc_ins_buf_server);



    /* header encode */
    ret = xqc_qpack_enc_headers(qpk_client, 0, &hdrs_in, efs_buf_client);
    CU_ASSERT(ret == XQC_OK && efs_buf_client->data_len > 0 && enc_ins_buf_client->data_len > 0);

    /* exceed max blocked stream, shall send as literal or ref, no encoder ins generated */
    size_t old_enc_len = enc_ins_buf_client->data_len;
    ret = xqc_qpack_enc_headers(qpk_client, 1, &hdrs_in2, efs_buf_server);
    CU_ASSERT(ret == XQC_OK && efs_buf_client->data_len > 0 && enc_ins_buf_client->data_len == old_enc_len);

    /* decode stream 0, shall be blocked */
    void *req_ctx = xqc_qpack_create_req_ctx(0);
    read = xqc_qpack_dec_headers(qpk_server, req_ctx, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out, XQC_H3_MAX_FIELD_SECTION_SIZE, 1, &blocked);
    CU_ASSERT(read > 0 && blocked == XQC_TRUE);
    efs_buf_client->consumed_len += read;

    /* try again will do nothing */
    read = xqc_qpack_dec_headers(qpk_server, req_ctx, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out, XQC_H3_MAX_FIELD_SECTION_SIZE, 1, &blocked);
    CU_ASSERT(read == 0 && blocked == XQC_TRUE);
    efs_buf_client->consumed_len += read;


    /* decode stream 1, shall not be blocked */
    xqc_bool_t blocked2 = XQC_FALSE;
    void *req_ctx2 = xqc_qpack_create_req_ctx(1);
    while (efs_buf_server->consumed_len < efs_buf_server->data_len) {
        read = xqc_qpack_dec_headers(qpk_server, req_ctx2, efs_buf_server->data + efs_buf_server->consumed_len, 1, &hdrs_out2, XQC_H3_MAX_FIELD_SECTION_SIZE, 1, &blocked);

        CU_ASSERT(read == 1);
        efs_buf_server->consumed_len += read;
    }
    CU_ASSERT(efs_buf_server->data_len == efs_buf_server->data_len && blocked2 == XQC_FALSE);
    efs_buf_server->consumed_len += read;
    xqc_qpack_destroy_req_ctx(req_ctx2);

    /* input encoder instruction into decoder */
    while (enc_ins_buf_client->consumed_len < enc_ins_buf_client->data_len) {
        read = xqc_qpack_process_encoder(qpk_server, enc_ins_buf_client->data + enc_ins_buf_client->consumed_len, 1);
        CU_ASSERT(read == 1);
        enc_ins_buf_client->consumed_len++;
    }
    CU_ASSERT(dec_ins_buf_server->data_len > 0);
    xqc_var_buf_clear(enc_ins_buf_client);


    /* decode blocked stream, shall finish */
    blocked = XQC_FALSE;
    read = xqc_qpack_dec_headers(qpk_server, req_ctx, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out, XQC_H3_MAX_FIELD_SECTION_SIZE, 1, &blocked);
    CU_ASSERT(read > 0);
    efs_buf_client->consumed_len += read;
    CU_ASSERT(blocked == XQC_FALSE && (efs_buf_client->data_len == efs_buf_client->consumed_len));
    xqc_qpack_destroy_req_ctx(req_ctx);

    /* input decoder's instruction into encoder */
    while (dec_ins_buf_server->consumed_len < dec_ins_buf_server->data_len) {
        read = xqc_qpack_process_decoder(qpk_client, dec_ins_buf_server->data + dec_ins_buf_server->consumed_len, 1);
        CU_ASSERT(read == 1);
        dec_ins_buf_server->consumed_len++;
    }

    /* encode again, can insert into dtable again */
    xqc_var_buf_clear(enc_ins_buf_client);
    xqc_var_buf_clear(efs_buf_server);
    ret = xqc_qpack_enc_headers(qpk_client, 2, &hdrs_in2, efs_buf_server);
    CU_ASSERT(ret == XQC_OK && efs_buf_server->data_len > 0 && enc_ins_buf_client->data_len > 0);


    xqc_var_buf_free(efs_buf_client);
    xqc_var_buf_free(enc_ins_buf_client);
    xqc_var_buf_free(dec_ins_buf_client);
    xqc_var_buf_free(efs_buf_server);
    xqc_var_buf_free(enc_ins_buf_server);
    xqc_var_buf_free(dec_ins_buf_server);

    xqc_h3_headers_free(&hdrs_out);
    xqc_h3_headers_free(&hdrs_out2);

    xqc_qpack_destroy(qpk_client);
    xqc_qpack_destroy(qpk_server);

    xqc_engine_destroy(engine);
}


void
xqc_qpack_test_duplicate()
{
    xqc_int_t ret = XQC_OK;
    xqc_var_buf_t *efs_buf_client = xqc_var_buf_create(32*1024);
    xqc_var_buf_t *enc_ins_buf_client = xqc_var_buf_create(16384);
    xqc_var_buf_t *dec_ins_buf_client = xqc_var_buf_create(16384);
    xqc_ins_buf_t buf_client = {enc_ins_buf_client, dec_ins_buf_client};

    xqc_var_buf_t *efs_buf_server = xqc_var_buf_create(32*1024);
    xqc_var_buf_t *enc_ins_buf_server = xqc_var_buf_create(16384);
    xqc_var_buf_t *dec_ins_buf_server = xqc_var_buf_create(16384);
    xqc_ins_buf_t buf_server = {enc_ins_buf_server, dec_ins_buf_server};

    // xqc_qpack_ins_cb_t ins_cb = {xqc_on_ins_enc_cb_normal, xqc_on_ins_dec_cb_normal};

    xqc_bool_t blocked = XQC_FALSE;

    xqc_http_header_t header_in[] = {
        {
            .name   = {.iov_base = "nm_00", .iov_len = 5},
            .value  = {.iov_base = "vlu_0", .iov_len = 5},  /* 42 */
        },
        {
            .name   = {.iov_base = "name_with_20b_000000", .iov_len = 20},
            .value  = {.iov_base = "value_with_360_b_1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111", .iov_len = 360},     /* 412, total to 454, exceed 448, make the first entry draining */
        }
    };
    size_t header_in_cnt = sizeof(header_in) / sizeof(header_in[0]);
    xqc_http_headers_t hdrs_in = {
        header_in, header_in_cnt, XQC_TEST_ENCODER_MAX_HEADERS
    };

    xqc_http_header_t header_draining[] = {
        {
            .name   = {.iov_base = "nm_00", .iov_len = 5},
            .value  = {.iov_base = "vlu_0", .iov_len = 5},  /* draining, shall trigger duplicate */
        }
    };

    xqc_http_headers_t hdrs_out;
    xqc_h3_headers_create_buf(&hdrs_out, XQC_TEST_ENCODER_MAX_HEADERS);

    xqc_http_headers_t hdrs_out_draining;
    xqc_h3_headers_create_buf(&hdrs_out_draining, XQC_TEST_ENCODER_MAX_HEADERS);


    ssize_t read = 0;



    /* encoder side */
    xqc_engine_t *engine = test_create_engine();

    xqc_qpack_t *qpk_client = xqc_qpack_create(512, 512, engine->log, &ins_cb, &buf_client);

    CU_ASSERT(qpk_client != NULL);
    ret = xqc_qpack_set_enc_max_dtable_cap(qpk_client, 512);
    CU_ASSERT(ret == XQC_OK);
    xqc_qpack_set_enc_insert_limit(qpk_client, 0.25, 1);
    /* set encoder's blocked streams, pretending it as SETTINGS from decoder */
    ret = xqc_qpack_set_max_blocked_stream(qpk_client, 16);
    CU_ASSERT(ret == XQC_OK);
    /* set encoder's dtable cap. pretending it as SETTINGS from decoder, and set dtable cap ins generated */
    ret = xqc_qpack_set_dtable_cap(qpk_client, 512);
    CU_ASSERT(ret == XQC_OK && enc_ins_buf_client->data_len > 0);


    /* decoder side */
    xqc_qpack_t *qpk_server = xqc_qpack_create(512, 512, engine->log, &ins_cb, &buf_server);

    CU_ASSERT(qpk_server != NULL);
    ret = xqc_qpack_set_enc_max_dtable_cap(qpk_server, 512);
    CU_ASSERT(ret == XQC_OK);
    xqc_qpack_set_enc_insert_limit(qpk_server, 0.25, 1);
    ret = xqc_qpack_set_max_blocked_stream(qpk_server, 16);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_qpack_set_dtable_cap(qpk_server, 512);
    CU_ASSERT(ret == XQC_OK && enc_ins_buf_server->data_len > 0);

    /* server received client's set max dynamic table capacity */
    read = xqc_qpack_process_encoder(qpk_server, enc_ins_buf_client->data, enc_ins_buf_client->data_len);
    CU_ASSERT(read == enc_ins_buf_client->data_len);
    xqc_var_buf_clear(enc_ins_buf_client);

    /* client received server's set max dynamic table capacity */
    read = xqc_qpack_process_encoder(qpk_client, enc_ins_buf_server->data, enc_ins_buf_server->data_len);
    CU_ASSERT(read == enc_ins_buf_server->data_len);
    xqc_var_buf_clear(enc_ins_buf_server);

    /* encode header_in, 5 insert instructions generated */
    ret = xqc_qpack_enc_headers(qpk_client, 0, &hdrs_in, efs_buf_client);
    CU_ASSERT(ret == XQC_OK && efs_buf_client->data_len > 0 && enc_ins_buf_client->data_len > 0);

    /* server received client's encoder instructions, all bytes consumed, decoder instruction generated */
    read = xqc_qpack_process_encoder(qpk_server, enc_ins_buf_client->data, enc_ins_buf_client->data_len);
    CU_ASSERT(read == enc_ins_buf_client->data_len && dec_ins_buf_server->data_len > 0);
    xqc_var_buf_clear(enc_ins_buf_client);

    /* server received headers frame */
    void *req_ctx_0 = xqc_qpack_create_req_ctx(0);
    read = xqc_qpack_dec_headers(qpk_server, req_ctx_0, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out, XQC_H3_MAX_FIELD_SECTION_SIZE, 1, &blocked);
    CU_ASSERT(read == efs_buf_client->data_len && hdrs_out.count == header_in_cnt);
    efs_buf_client->consumed_len += read;
    for (size_t i = 0; i < header_in_cnt && i < hdrs_out.count; i++) {
        CU_ASSERT(memcmp(header_in[i].name.iov_base, hdrs_out.headers[i].name.iov_base,
                         header_in[i].name.iov_len) == 0);
        CU_ASSERT(memcmp(header_in[i].value.iov_base, hdrs_out.headers[i].value.iov_base, 
                         header_in[i].value.iov_len) == 0);
    }
    xqc_var_buf_clear(efs_buf_client);
    // xqc_h3_headers_free(&hdrs_out);
    xqc_qpack_destroy_req_ctx(req_ctx_0);

    /* client received server's decoder instructions */
    read = xqc_qpack_process_decoder(qpk_client, dec_ins_buf_server->data, dec_ins_buf_server->data_len);
    CU_ASSERT(read == dec_ins_buf_server->data_len);
    xqc_var_buf_clear(dec_ins_buf_server);

    /* encode header_draining, duplicate instruction generated */
    hdrs_in.headers = (xqc_http_header_t *)&header_draining;
    hdrs_in.count = 1;
    ret = xqc_qpack_enc_headers(qpk_client, 1, &hdrs_in, efs_buf_client);
    CU_ASSERT(ret == XQC_OK && efs_buf_client->data_len > 0 && enc_ins_buf_client->data_len > 0);

    /* process duplicate instruction */
    read = xqc_qpack_process_encoder(qpk_server, enc_ins_buf_client->data, enc_ins_buf_client->data_len);
    CU_ASSERT(read == enc_ins_buf_client->data_len && dec_ins_buf_server->data_len > 0);
    xqc_var_buf_clear(enc_ins_buf_client);


    /* decode header */
    void *req_ctx_1 = xqc_qpack_create_req_ctx(1);
    read = xqc_qpack_dec_headers(qpk_server, req_ctx_1, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out_draining, XQC_H3_MAX_FIELD_SECTION_SIZE, 1,
                                 &blocked);
    CU_ASSERT(read == efs_buf_client->data_len && hdrs_out_draining.count == 1);
    efs_buf_client->consumed_len += read;
    CU_ASSERT(memcmp(header_in[0].name.iov_base, hdrs_out_draining.headers[0].name.iov_base,
                        header_in[0].name.iov_len) == 0);
    CU_ASSERT(memcmp(header_in[0].value.iov_base, hdrs_out_draining.headers[0].value.iov_base,
                        header_in[0].value.iov_len) == 0);
    // xqc_h3_headers_free(&hdrs_out_draining);
    xqc_qpack_destroy_req_ctx(req_ctx_1);


    /* client received insert count increment and section ack */
    read = xqc_qpack_process_decoder(qpk_client, dec_ins_buf_server->data, dec_ins_buf_server->data_len);
    CU_ASSERT(read == dec_ins_buf_server->data_len);
    xqc_var_buf_clear(dec_ins_buf_server);

    /* all entries acked, dtable is able to set to be 0 */
    ret = xqc_qpack_set_dtable_cap(qpk_client, 0);
    CU_ASSERT(ret == XQC_OK);


    xqc_var_buf_free(efs_buf_client);
    xqc_var_buf_free(enc_ins_buf_client);
    xqc_var_buf_free(dec_ins_buf_client);
    xqc_var_buf_free(efs_buf_server);
    xqc_var_buf_free(enc_ins_buf_server);
    xqc_var_buf_free(dec_ins_buf_server);

    xqc_h3_headers_free(&hdrs_out);
    xqc_h3_headers_free(&hdrs_out_draining);

    xqc_qpack_destroy(qpk_client);
    xqc_qpack_destroy(qpk_server);
    xqc_engine_destroy(engine);
}



const unsigned char chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
void
xqc_gen_rand_str(char *dst, size_t len)
{
    srandom(time(NULL));
    for (size_t i = 0; i < len; i++) {
        /* one of the 62 characters, not the terminating NUL */
        dst[i] = chars[random() % (sizeof(chars) - 1)];
    }
}

void
xqc_qpack_test_robust()
{
    xqc_int_t ret = XQC_OK;
    xqc_var_buf_t *efs_buf_client = xqc_var_buf_create(32*1024);
    xqc_var_buf_t *enc_ins_buf_client = xqc_var_buf_create(16384);
    xqc_var_buf_t *dec_ins_buf_client = xqc_var_buf_create(16384);
    xqc_ins_buf_t buf_client = {enc_ins_buf_client, dec_ins_buf_client};

    xqc_var_buf_t *efs_buf_server = xqc_var_buf_create(32*1024);
    xqc_var_buf_t *enc_ins_buf_server = xqc_var_buf_create(16384);
    xqc_var_buf_t *dec_ins_buf_server = xqc_var_buf_create(16384);
    xqc_ins_buf_t buf_server = {enc_ins_buf_server, dec_ins_buf_server};

    xqc_bool_t blocked = XQC_FALSE;

    static const size_t header_in_cnt = 128;

    xqc_http_header_t header_in[header_in_cnt];
    for (size_t i = 0; i < header_in_cnt; i++) {
        xqc_http_header_t *hdr = header_in + i;
        memset(hdr, 0, sizeof(*hdr));

        size_t nlen = (random() & 255) + 1;
        hdr->name.iov_base = calloc(1, nlen + 1);
        hdr->name.iov_len = nlen;
        xqc_gen_rand_str(hdr->name.iov_base, nlen);

        size_t vlen = (random() & 8191) + 1;
        hdr->value.iov_base = calloc(1, vlen + 1);
        hdr->value.iov_len = vlen;
        xqc_gen_rand_str(hdr->value.iov_base, vlen);
    }


    xqc_http_headers_t hdrs_in = {
        header_in, header_in_cnt, header_in_cnt
    };


    xqc_http_headers_t hdrs_out;
    xqc_h3_headers_create_buf(&hdrs_out, header_in_cnt);

    ssize_t read = 0;
    size_t recvd = 0;


    /* encoder side */
    xqc_engine_t *engine = test_create_engine();

    xqc_qpack_t *qpk_client = xqc_qpack_create(16*1024, 16*1024, engine->log, &ins_cb, &buf_client);

    CU_ASSERT(qpk_client != NULL);
    ret = xqc_qpack_set_enc_max_dtable_cap(qpk_client, 16*1024);
    CU_ASSERT(ret == XQC_OK);
    xqc_qpack_set_enc_insert_limit(qpk_client, 0.25, 1);
    /* set encoder's blocked streams, pretending it as SETTINGS from decoder */
    ret = xqc_qpack_set_max_blocked_stream(qpk_client, 16);
    CU_ASSERT(ret == XQC_OK);
    /* set encoder's dtable cap. pretending it as SETTINGS from decoder, and set dtable cap ins generated */
    ret = xqc_qpack_set_dtable_cap(qpk_client, 16*1024);
    CU_ASSERT(ret == XQC_OK && enc_ins_buf_client->data_len > 0);


    /* decoder side */
    xqc_qpack_t *qpk_server = xqc_qpack_create(16*1024, 16*1024, engine->log, &ins_cb, &buf_server);

    CU_ASSERT(qpk_server != NULL);
    ret = xqc_qpack_set_enc_max_dtable_cap(qpk_server, 16*1024);
    CU_ASSERT(ret == XQC_OK);
    xqc_qpack_set_enc_insert_limit(qpk_server, 0.25, 1);
    ret = xqc_qpack_set_max_blocked_stream(qpk_server, 16);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_qpack_set_dtable_cap(qpk_server, 16*1024);
    CU_ASSERT(ret == XQC_OK && enc_ins_buf_server->data_len > 0);

    /* server received client's set max dynamic table capacity */
    read = xqc_qpack_process_encoder(qpk_server, enc_ins_buf_client->data, enc_ins_buf_client->data_len);
    CU_ASSERT(read == enc_ins_buf_client->data_len);
    xqc_var_buf_clear(enc_ins_buf_client);

    /* client received server's set max dynamic table capacity */
    read = xqc_qpack_process_encoder(qpk_client, enc_ins_buf_server->data, enc_ins_buf_server->data_len);
    CU_ASSERT(read == enc_ins_buf_server->data_len);
    xqc_var_buf_clear(enc_ins_buf_server);



    /* encode header_in */
    ret = xqc_qpack_enc_headers(qpk_client, 0, &hdrs_in, efs_buf_client);
    CU_ASSERT(ret == XQC_OK && efs_buf_client->data_len > 0 && enc_ins_buf_client->data_len > 0);

    /* decoder received encoder instruction */
    ret = xqc_qpack_process_encoder(qpk_server, enc_ins_buf_client->data, enc_ins_buf_client->data_len);
    CU_ASSERT(ret == enc_ins_buf_client->data_len && dec_ins_buf_server->data_len > 0);
    xqc_var_buf_clear(enc_ins_buf_client);

    /* server decode headers */
    void *req_ctx_0 = xqc_qpack_create_req_ctx(0);
    ret = xqc_qpack_dec_headers(qpk_server, req_ctx_0, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out, UINT64_MAX, 1, &blocked);
    CU_ASSERT(ret == efs_buf_client->data_len && dec_ins_buf_server->data_len > 0
              && hdrs_out.count == hdrs_in.count);
    efs_buf_client->consumed_len += read;
    if (hdrs_out.count == hdrs_in.count)
    {
        for (int i = 0; i < hdrs_in.count; i++) {
            CU_ASSERT(memcmp(header_in[i].name.iov_base, hdrs_out.headers[i].name.iov_base,
                            header_in[i].name.iov_len) == 0);
            CU_ASSERT(memcmp(header_in[i].value.iov_base, hdrs_out.headers[i].value.iov_base, 
                            header_in[i].value.iov_len) == 0);
        }
    }
    xqc_var_buf_clear(efs_buf_client);
    xqc_qpack_destroy_req_ctx(req_ctx_0);

    /* client received server's decoder instruction */
    ret = xqc_qpack_process_decoder(qpk_client, dec_ins_buf_server->data, dec_ins_buf_server->data_len);
    CU_ASSERT(ret == dec_ins_buf_server->data_len);
    xqc_var_buf_clear(dec_ins_buf_server);


    xqc_var_buf_free(efs_buf_client);
    xqc_var_buf_free(enc_ins_buf_client);
    xqc_var_buf_free(dec_ins_buf_client);
    xqc_var_buf_free(efs_buf_server);
    xqc_var_buf_free(enc_ins_buf_server);
    xqc_var_buf_free(dec_ins_buf_server);

    xqc_h3_headers_clear(&hdrs_in);
    xqc_h3_headers_free(&hdrs_out);

    xqc_qpack_destroy(qpk_client);
    xqc_qpack_destroy(qpk_server);
    xqc_engine_destroy(engine);
}


void
xqc_test_min_ref()
{
    xqc_int_t ret = XQC_OK;
    xqc_var_buf_t *efs_buf_client = xqc_var_buf_create(32*1024);
    xqc_var_buf_t *efs_buf_client2 = xqc_var_buf_create(32*1024);
    xqc_var_buf_t *enc_ins_buf_client = xqc_var_buf_create(16384);
    xqc_var_buf_t *dec_ins_buf_client = xqc_var_buf_create(16384);
    xqc_ins_buf_t ins_buf_client = {enc_ins_buf_client, dec_ins_buf_client};

    xqc_var_buf_t *efs_buf_server = xqc_var_buf_create(32*1024);
    xqc_var_buf_t *enc_ins_buf_server = xqc_var_buf_create(16384);
    xqc_var_buf_t *dec_ins_buf_server = xqc_var_buf_create(16384);
    xqc_ins_buf_t ins_buf_server = {enc_ins_buf_server, dec_ins_buf_server};
    xqc_bool_t blocked = XQC_FALSE;

    xqc_http_header_t header[XQC_TEST_ENCODER_MAX_HEADERS] = {
        {
            .name   = {.iov_base = "test_header_0001", .iov_len = 16},
            .value  = {.iov_base = "test_value_00001", .iov_len = 16},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "test_header_0002", .iov_len = 16},
            .value  = {.iov_base = "test_value_00002", .iov_len = 16},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "test_header_0003", .iov_len = 16},
            .value  = {.iov_base = "test_value_00003", .iov_len = 16},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "test_header_0004", .iov_len = 16},
            .value  = {.iov_base = "test_value_00004", .iov_len = 16},
            .flags  = 0,
        },
    };

    xqc_http_headers_t hdrs1 = {
        header, 4, XQC_TEST_ENCODER_MAX_HEADERS
    };

    xqc_http_header_t header2[XQC_TEST_ENCODER_MAX_HEADERS] = {
        {
            .name   = {.iov_base = "test_header_0002", .iov_len = 16},
            .value  = {.iov_base = "test_value_00002", .iov_len = 16},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "test_header_0003", .iov_len = 16},
            .value  = {.iov_base = "test_value_00003", .iov_len = 16},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "test_header_0004", .iov_len = 16},
            .value  = {.iov_base = "test_value_00004", .iov_len = 16},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "test_header_0005", .iov_len = 16},
            .value  = {.iov_base = "test_value_00005", .iov_len = 16},
            .flags  = 0,
        },
    };

    xqc_http_headers_t hdrs2 = {
        header2, 4, XQC_TEST_ENCODER_MAX_HEADERS
    };

    xqc_http_header_t header_out[XQC_TEST_ENCODER_MAX_HEADERS];
    xqc_http_headers_t hdrs_out = {
        header_out, 0, XQC_TEST_ENCODER_MAX_HEADERS
    };

    xqc_http_header_t header_out2[XQC_TEST_ENCODER_MAX_HEADERS];
    xqc_http_headers_t hdrs_out2 = {
        header_out2, 0, XQC_TEST_ENCODER_MAX_HEADERS
    };

    ssize_t read = 0;
    size_t recvd = 0;

    /* encoder side */
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);

    xqc_qpack_t *qpk_client = xqc_qpack_create(16384, 16384, engine->log, &ins_cb, &ins_buf_client);
    CU_ASSERT(qpk_client != NULL);

    ret = xqc_qpack_set_enc_max_dtable_cap(qpk_client, 256);
    CU_ASSERT(ret == XQC_OK);
    xqc_qpack_set_enc_insert_limit(qpk_client, 0.25, 0.75);
    /* set encoder's blocked streams, pretending it as SETTINGS from decoder */
    ret = xqc_qpack_set_max_blocked_stream(qpk_client, 16);
    CU_ASSERT(ret == XQC_OK);
    /* set encoder's dtable cap. pretending it as SETTINGS from decoder, and set dtable cap ins generated */
    ret = xqc_qpack_set_dtable_cap(qpk_client, 256);
    CU_ASSERT(ret == XQC_OK && enc_ins_buf_client->data_len > 0);


    /* decoder side */
    xqc_qpack_t *qpk_server = xqc_qpack_create(16384, 16384, engine->log, &ins_cb, &ins_buf_server);
    CU_ASSERT(qpk_server != NULL);

    ret = xqc_qpack_set_enc_max_dtable_cap(qpk_server, 256);
    CU_ASSERT(ret == XQC_OK);
    xqc_qpack_set_enc_insert_limit(qpk_server, 0.25, 0.75);
    ret = xqc_qpack_set_max_blocked_stream(qpk_server, 16);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_qpack_set_dtable_cap(qpk_server, 256);
    CU_ASSERT(ret == XQC_OK && enc_ins_buf_server->data_len > 0);


    /* server received Set Dynamic Table Capacity from client */
    read = xqc_qpack_process_encoder(qpk_server, enc_ins_buf_client->data, enc_ins_buf_client->data_len);
    CU_ASSERT(read == enc_ins_buf_client->data_len);
    xqc_var_buf_clear(enc_ins_buf_client);

    /* client received Set Dynamic Table Capacity from server */
    read = xqc_qpack_process_encoder(qpk_client, enc_ins_buf_server->data, enc_ins_buf_server->data_len);
    CU_ASSERT(read == enc_ins_buf_server->data_len);
    xqc_var_buf_clear(enc_ins_buf_server);


    /* header encode */
    ret = xqc_qpack_enc_headers(qpk_client, 0, &hdrs1, efs_buf_client);
    CU_ASSERT(ret == XQC_OK && efs_buf_client->data_len > 0 && enc_ins_buf_client->data_len > 0);

    /* header encode */
    ret = xqc_qpack_enc_headers(qpk_client, 4, &hdrs2, efs_buf_client2);
    CU_ASSERT(ret == XQC_OK && efs_buf_client2->data_len > 0 && enc_ins_buf_client->data_len > 0);


    ssize_t processed = xqc_qpack_process_encoder(qpk_server, ins_buf_client.enc_ins->data,
        ins_buf_client.enc_ins->data_len);
    CU_ASSERT(processed > 0);
    xqc_var_buf_clear(ins_buf_client.enc_ins);

    xqc_rep_ctx_t *rep_ctx1 = xqc_qpack_create_req_ctx(0);
    processed = xqc_qpack_dec_headers(qpk_server, rep_ctx1, efs_buf_client->data, efs_buf_client->data_len, &hdrs_out, XQC_H3_MAX_FIELD_SECTION_SIZE, XQC_TRUE, &blocked);
    CU_ASSERT(processed == efs_buf_client->data_len);


    xqc_rep_ctx_t *rep_ctx2 = xqc_qpack_create_req_ctx(4);
    processed = xqc_qpack_dec_headers(qpk_server, rep_ctx2, efs_buf_client2->data, efs_buf_client2->data_len, &hdrs_out2, XQC_H3_MAX_FIELD_SECTION_SIZE, XQC_TRUE, &blocked);
    CU_ASSERT(processed == efs_buf_client2->data_len);

    xqc_h3_headers_clear(&hdrs_out);
    xqc_h3_headers_clear(&hdrs_out2);

    xqc_qpack_destroy_req_ctx(rep_ctx1);
    xqc_qpack_destroy_req_ctx(rep_ctx2);

    xqc_var_buf_free(efs_buf_client);
    xqc_var_buf_free(efs_buf_client2);
    xqc_var_buf_free(enc_ins_buf_client);
    xqc_var_buf_free(dec_ins_buf_client);
    xqc_var_buf_free(efs_buf_server);
    xqc_var_buf_free(enc_ins_buf_server);
    xqc_var_buf_free(dec_ins_buf_server);

    xqc_qpack_destroy(qpk_client);
    xqc_qpack_destroy(qpk_server);

    xqc_engine_destroy(engine);

}



static xqc_usec_t xqc_qpack_test_duplicate_now;


static xqc_usec_t
xqc_qpack_test_duplicate_timestamp(void)
{
    return xqc_qpack_test_duplicate_now;
}


static ssize_t
xqc_qpack_test_process_duplicate(xqc_qpack_t *qpk, xqc_var_buf_t *enc_ins)
{
    xqc_var_buf_clear(enc_ins);
    if (xqc_ins_write_dup(enc_ins, 0) != XQC_OK) {
        return XQC_ERROR;
    }

    return xqc_qpack_process_encoder(qpk, enc_ins->data, enc_ins->data_len);
}


static void
xqc_qpack_test_duplicate_work_limit()
{
    unsigned char name[100];
    xqc_var_buf_t *enc_ins = xqc_var_buf_create(1024);
    xqc_var_buf_t *dec_ins = xqc_var_buf_create(1024);
    xqc_ins_buf_t ins_buf = {enc_ins, dec_ins};
    xqc_engine_t *engine = test_create_engine();
    xqc_qpack_t *qpk = NULL;
    xqc_timestamp_pt saved_timestamp;
    ssize_t read;

    CU_ASSERT_FATAL(engine != NULL);
    CU_ASSERT_FATAL(enc_ins != NULL);
    CU_ASSERT_FATAL(dec_ins != NULL);
    memset(name, 'a', sizeof(name));

    qpk = xqc_qpack_create(528, 528, engine->log, &ins_cb, &ins_buf);
    CU_ASSERT_FATAL(qpk != NULL);

    saved_timestamp = xqc_monotonic_timestamp;
    xqc_qpack_test_duplicate_now = 1000000;
    xqc_monotonic_timestamp = xqc_qpack_test_duplicate_timestamp;

    CU_ASSERT(xqc_ins_write_set_dtable_cap(enc_ins, 528) == XQC_OK);
    CU_ASSERT(xqc_ins_write_insert_literal_name(enc_ins, name, sizeof(name),
                                                NULL, 0) == XQC_OK);
    read = xqc_qpack_process_encoder(qpk, enc_ins->data, enc_ins->data_len);
    CU_ASSERT(read == enc_ins->data_len);
    CU_ASSERT(xqc_qpack_get_dec_insert_count(qpk) == 1);

    /* Seven 132-byte copies exceed one table capacity but remain below the hard limit. */
    for (int i = 0; i < 7; i++) {
        read = xqc_qpack_test_process_duplicate(qpk, enc_ins);
        CU_ASSERT(read == enc_ins->data_len);
    }
    CU_ASSERT(xqc_qpack_get_dec_insert_count(qpk) == 8);

    /* A new second clears the per-second duplicate-work accounting. */
    xqc_qpack_test_duplicate_now += 1000000;
    for (int i = 0; i < 7; i++) {
        read = xqc_qpack_test_process_duplicate(qpk, enc_ins);
        CU_ASSERT(read == enc_ins->data_len);
    }
    CU_ASSERT(xqc_qpack_get_dec_insert_count(qpk) == 15);

    xqc_qpack_test_duplicate_now += 1000000;
    /* Sixteen copies exactly reach 4 * 528 and must remain allowed. */
    for (int i = 0; i < 16; i++) {
        read = xqc_qpack_test_process_duplicate(qpk, enc_ins);
        CU_ASSERT(read == enc_ins->data_len);
    }
    read = xqc_qpack_test_process_duplicate(qpk, enc_ins);
    CU_ASSERT(read == -XQC_QPACK_DYNAMIC_TABLE_EXCESSIVE_LOAD);
    CU_ASSERT(xqc_qpack_get_dec_insert_count(qpk) == 31);

    xqc_monotonic_timestamp = saved_timestamp;
    xqc_qpack_destroy(qpk);
    xqc_var_buf_free(enc_ins);
    xqc_var_buf_free(dec_ins);
    xqc_engine_destroy(engine);
}


static void
xqc_qpack_test_field_section_limit()
{
    const unsigned char field_section[] = { 0x00, 0x00, 0xc0 };
    xqc_engine_t *engine = test_create_engine();
    xqc_ins_buf_t ins_buf = { NULL, NULL };
    xqc_qpack_t *qpk;
    xqc_http_headers_t headers;
    xqc_rep_ctx_t *req_ctx;
    xqc_bool_t blocked = XQC_FALSE;
    ssize_t processed;

    CU_ASSERT_FATAL(engine != NULL);
    qpk = xqc_qpack_create(0, 0, engine->log, &ins_cb, &ins_buf);
    CU_ASSERT_FATAL(qpk != NULL);

    memset(&headers, 0, sizeof(headers));
    req_ctx = xqc_qpack_create_req_ctx(0);
    CU_ASSERT_FATAL(req_ctx != NULL);
    processed = xqc_qpack_dec_headers(qpk, req_ctx,
                                      (unsigned char *)field_section,
                                      sizeof(field_section), &headers, 42,
                                      XQC_FALSE, &blocked);
    CU_ASSERT_EQUAL(processed, sizeof(field_section));
    CU_ASSERT_EQUAL(headers.count, 1);
    CU_ASSERT_EQUAL(headers.total_len, 10);
    CU_ASSERT_EQUAL(blocked, XQC_FALSE);
    xqc_h3_headers_free(&headers);
    xqc_qpack_destroy_req_ctx(req_ctx);

    memset(&headers, 0, sizeof(headers));
    req_ctx = xqc_qpack_create_req_ctx(4);
    CU_ASSERT_FATAL(req_ctx != NULL);
    processed = xqc_qpack_dec_headers(qpk, req_ctx,
                                      (unsigned char *)field_section,
                                      sizeof(field_section), &headers, 41,
                                      XQC_FALSE, &blocked);
    CU_ASSERT_EQUAL(processed, -XQC_H3_INVALID_HEADER);
    CU_ASSERT_EQUAL(headers.count, 0);
    CU_ASSERT_PTR_NULL(headers.headers[0].name.iov_base);
    CU_ASSERT_PTR_NULL(headers.headers[0].value.iov_base);
    xqc_h3_headers_free(&headers);
    xqc_qpack_destroy_req_ctx(req_ctx);

    xqc_qpack_destroy(qpk);
    xqc_engine_destroy(engine);
}


static void
xqc_qpack_test_blocked_field_section_limit()
{
    static const unsigned char encoder_ins[] = {
        0x3f, 0x61, 0x41, 'a', 0x01, 'b'
    };
    static const unsigned char field_section[] = {
        0x02, 0x00,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
    };
    xqc_engine_t *engine = test_create_engine();
    xqc_var_buf_t *dec_ins_buf = xqc_var_buf_create(128);
    xqc_ins_buf_t ins_buf = { NULL, dec_ins_buf };
    xqc_qpack_t *qpk;
    xqc_http_headers_t headers;
    xqc_rep_ctx_t *req_ctx;
    xqc_bool_t blocked = XQC_FALSE;
    ssize_t processed;

    CU_ASSERT_FATAL(engine != NULL);
    CU_ASSERT_FATAL(dec_ins_buf != NULL);
    qpk = xqc_qpack_create(0, 128, engine->log, &ins_cb, &ins_buf);
    CU_ASSERT_FATAL(qpk != NULL);

    memset(&headers, 0, sizeof(headers));
    req_ctx = xqc_qpack_create_req_ctx(0);
    CU_ASSERT_FATAL(req_ctx != NULL);

    processed = xqc_qpack_dec_headers(qpk, req_ctx,
                                      (unsigned char *)field_section,
                                      sizeof(field_section), &headers, 512,
                                      XQC_FALSE, &blocked);
    CU_ASSERT_EQUAL(processed, 2);
    CU_ASSERT_EQUAL(blocked, XQC_TRUE);
    CU_ASSERT_EQUAL(headers.count, 0);

    processed = xqc_qpack_process_encoder(qpk, (unsigned char *)encoder_ins,
                                          sizeof(encoder_ins));
    CU_ASSERT_EQUAL(processed, sizeof(encoder_ins));

    blocked = XQC_FALSE;
    processed = xqc_qpack_dec_headers(qpk, req_ctx,
                                      (unsigned char *)field_section + 2,
                                      sizeof(field_section) - 2, &headers, 512,
                                      XQC_TRUE, &blocked);
    CU_ASSERT_EQUAL(processed, -XQC_H3_INVALID_HEADER);
    CU_ASSERT_EQUAL(blocked, XQC_FALSE);
    CU_ASSERT_EQUAL(headers.count, 15);
    CU_ASSERT_EQUAL(headers.total_len, 30);
    CU_ASSERT_PTR_NULL(headers.headers[15].name.iov_base);
    CU_ASSERT_PTR_NULL(headers.headers[15].value.iov_base);

    xqc_h3_headers_free(&headers);
    xqc_qpack_destroy_req_ctx(req_ctx);
    xqc_qpack_destroy(qpk);
    xqc_var_buf_free(dec_ins_buf);
    xqc_engine_destroy(engine);
}


void
xqc_qpack_test()
{
    xqc_qpack_test_basic();
    xqc_qpack_test_duplicate();
    xqc_qpack_test_robust();
    xqc_test_min_ref();
    xqc_qpack_test_duplicate_work_limit();
    xqc_qpack_test_field_section_limit();
    xqc_qpack_test_blocked_field_section_limit();
}


#ifdef XQC_TEST_ALLOC_WRAP

/*
 * Make the chunks that malloc hands out next hold garbage, as reused
 * memory does: a field the caller does not set is then not NULL.
 */
static void
xqc_qpack_test_dirty_heap(void)
{
    size_t  size;
    void   *chunk[64];

    for (size = 8; size <= 512; size += 8) {
        chunk[size / 8 - 1] = malloc(size);
        if (chunk[size / 8 - 1] != NULL) {
            memset(chunk[size / 8 - 1], 0xbe, size);
        }
    }

    for (size = 8; size <= 512; size += 8) {
        free(chunk[size / 8 - 1]);
    }
}

#define XQC_QPACK_TEST_PEERS_CAP        4096
#define XQC_QPACK_TEST_PEERS_ENTRIES    32

/*
 * An encoder whose dynamic table of 4096 bytes holds 32 entries, and a
 * decoder that received their instructions. The first entry, of 42 bytes,
 * is followed by 31 entries of 115 bytes, after which it is draining
 * (xqc_dtable_is_entry_draining()). The field section that refers to them
 * on stream 0 is not acknowledged: stream 0 is blocked already, and the
 * field sections encoded on it next add no blocked stream.
 */
typedef struct xqc_qpack_test_peers_s {
    xqc_qpack_t    *enc;
    xqc_ins_buf_t   enc_bufs;
    xqc_qpack_t    *dec;
    xqc_ins_buf_t   dec_bufs;
} xqc_qpack_test_peers_t;

static xqc_http_header_t g_qpack_test_draining = {
    .name   = {.iov_base = "nm_00", .iov_len = 5},
    .value  = {.iov_base = "vlu_0", .iov_len = 5},
};

static void
xqc_qpack_test_peers_create(xqc_engine_t *engine, xqc_qpack_test_peers_t *p)
{
    unsigned char       name[XQC_QPACK_TEST_PEERS_ENTRIES][3];
    unsigned char       value[80];
    xqc_http_header_t   hdr[XQC_QPACK_TEST_PEERS_ENTRIES];
    xqc_http_headers_t  hdrs = {hdr, XQC_QPACK_TEST_PEERS_ENTRIES,
                                XQC_QPACK_TEST_PEERS_ENTRIES};
    xqc_var_buf_t      *efs = xqc_var_buf_create(16384);
    xqc_var_buf_t      *ins;
    size_t              i;

    memset(hdr, 0, sizeof(hdr));
    memset(value, 'v', sizeof(value));
    hdr[0] = g_qpack_test_draining;
    for (i = 1; i < XQC_QPACK_TEST_PEERS_ENTRIES; i++) {
        name[i][0] = 'f';
        name[i][1] = '0' + i / 10;
        name[i][2] = '0' + i % 10;
        hdr[i].name.iov_base = name[i];
        hdr[i].name.iov_len = sizeof(name[i]);
        hdr[i].value.iov_base = value;
        hdr[i].value.iov_len = sizeof(value);
    }

    p->enc_bufs.enc_ins = xqc_var_buf_create(16384);
    p->enc_bufs.dec_ins = xqc_var_buf_create(16384);
    p->dec_bufs.enc_ins = xqc_var_buf_create(16384);
    p->dec_bufs.dec_ins = xqc_var_buf_create(16384);
    p->enc = xqc_qpack_create(XQC_QPACK_TEST_PEERS_CAP,
                              XQC_QPACK_TEST_PEERS_CAP, engine->log,
                              &ins_cb, &p->enc_bufs);
    p->dec = xqc_qpack_create(XQC_QPACK_TEST_PEERS_CAP,
                              XQC_QPACK_TEST_PEERS_CAP, engine->log,
                              &ins_cb, &p->dec_bufs);
    CU_ASSERT_FATAL(efs != NULL && p->enc != NULL && p->dec != NULL
                    && p->enc_bufs.enc_ins != NULL
                    && p->enc_bufs.dec_ins != NULL
                    && p->dec_bufs.enc_ins != NULL
                    && p->dec_bufs.dec_ins != NULL);

    /* the decoder's SETTINGS, and the encoder's dynamic table capacity */
    CU_ASSERT(xqc_qpack_set_enc_max_dtable_cap(p->enc,
                                               XQC_QPACK_TEST_PEERS_CAP)
              == XQC_OK);
    CU_ASSERT(xqc_qpack_set_max_blocked_stream(p->enc, 16) == XQC_OK);
    CU_ASSERT(xqc_qpack_set_dtable_cap(p->enc, XQC_QPACK_TEST_PEERS_CAP)
              == XQC_OK);

    CU_ASSERT(xqc_qpack_enc_headers(p->enc, 0, &hdrs, efs) == XQC_OK);
    ins = p->enc_bufs.enc_ins;
    CU_ASSERT(xqc_qpack_process_encoder(p->dec, ins->data, ins->data_len)
              == ins->data_len);
    CU_ASSERT(xqc_qpack_get_dec_insert_count(p->dec)
              == XQC_QPACK_TEST_PEERS_ENTRIES);
    xqc_var_buf_clear(ins);
    xqc_var_buf_free(efs);
}

static void
xqc_qpack_test_peers_destroy(xqc_qpack_test_peers_t *p)
{
    xqc_qpack_destroy(p->enc);
    xqc_qpack_destroy(p->dec);
    xqc_var_buf_free(p->enc_bufs.enc_ins);
    xqc_var_buf_free(p->enc_bufs.dec_ins);
    xqc_var_buf_free(p->dec_bufs.enc_ins);
    xqc_var_buf_free(p->dec_bufs.dec_ins);
}

/* the decoder decodes a field section of one field line, without waiting */
static void
xqc_qpack_test_peers_decode(xqc_qpack_test_peers_t *p, xqc_var_buf_t *efs,
    xqc_http_header_t *hdr)
{
    xqc_http_headers_t  out;
    xqc_http_header_t  *line;
    xqc_bool_t          blocked = XQC_FALSE;
    xqc_rep_ctx_t      *ctx = xqc_qpack_create_req_ctx(0);
    ssize_t             read;

    CU_ASSERT_FATAL(ctx != NULL);
    memset(&out, 0, sizeof(out));
    read = xqc_qpack_dec_headers(p->dec, ctx, efs->data, efs->data_len, &out,
                                 XQC_H3_MAX_FIELD_SECTION_SIZE, XQC_TRUE,
                                 &blocked);
    CU_ASSERT(read == efs->data_len);
    CU_ASSERT(blocked == XQC_FALSE);
    CU_ASSERT(out.count == 1);

    if (out.count == 1) {
        line = &out.headers[0];
        CU_ASSERT(line->name.iov_len == hdr->name.iov_len
                  && memcmp(line->name.iov_base, hdr->name.iov_base,
                            hdr->name.iov_len) == 0);
        CU_ASSERT(line->value.iov_len == hdr->value.iov_len
                  && memcmp(line->value.iov_base, hdr->value.iov_base,
                            hdr->value.iov_len) == 0);
    }

    xqc_h3_headers_free(&out);
    xqc_qpack_destroy_req_ctx(ctx);
}

/*
 * An entry that the encoder inserts, or duplicates, is in the decoder's
 * table once the decoder has every instruction the encoder wrote: field
 * lines that refer to an entry the decoder never inserts, or to a newer
 * one, would name another entry, or one the decoder waits for (RFC 9204
 * 3.2.4). On stream 0, the encoder encodes the field line into an
 * instruction buffer that every instruction outgrows: the Duplicate
 * instruction of the draining entry, 31 entries back, takes 2 bytes. Each
 * allocation of that encoding fails in turn, then the field line is
 * encoded again. The decoder receives every instruction, and decodes each
 * field section that was encoded.
 */
static void
xqc_qpack_test_enc_ins_sweep(xqc_engine_t *engine, xqc_http_header_t *hdr,
    xqc_bool_t compat)
{
    long                    n;
    int                     failed;
    xqc_int_t               ret;
    xqc_var_buf_t          *ins;
    xqc_var_buf_t          *efs;
    xqc_var_buf_t          *efs_again;
    xqc_http_headers_t      hdrs = {hdr, 1, 1};
    xqc_qpack_test_peers_t  p;

    for (n = 1; n < 100; n++) {
        xqc_test_alloc_live = 0;
        xqc_test_alloc_tracking = 1;
        xqc_qpack_test_peers_create(engine, &p);
#ifdef XQC_COMPAT_DUPLICATE
        xqc_qpack_set_compat_dup(p.enc, compat);
#endif
        efs = xqc_var_buf_create(256);
        efs_again = xqc_var_buf_create(256);
        CU_ASSERT_FATAL(efs != NULL && efs_again != NULL);

        xqc_var_buf_free(p.enc_bufs.enc_ins);
        p.enc_bufs.enc_ins = xqc_var_buf_create(1);
        CU_ASSERT_FATAL(p.enc_bufs.enc_ins != NULL);

        xqc_test_alloc_failed = 0;
        xqc_test_alloc_fail_at = n;
        xqc_test_alloc_count = 0;
        ret = xqc_qpack_enc_headers(p.enc, 0, &hdrs, efs);
        xqc_test_alloc_count = -1;
        failed = xqc_test_alloc_failed;

        CU_ASSERT(xqc_qpack_enc_headers(p.enc, 0, &hdrs, efs_again)
                  == XQC_OK);

        ins = p.enc_bufs.enc_ins;
        CU_ASSERT(xqc_qpack_process_encoder(p.dec, ins->data,
                                            ins->data_len)
                  == ins->data_len);
        if (ret == XQC_OK) {
            xqc_qpack_test_peers_decode(&p, efs, hdr);
        }
        xqc_qpack_test_peers_decode(&p, efs_again, hdr);

        xqc_var_buf_free(efs);
        xqc_var_buf_free(efs_again);
        xqc_qpack_test_peers_destroy(&p);
        xqc_test_alloc_tracking = 0;
        CU_ASSERT(xqc_test_alloc_live == 0);

        if (!failed) {
            /* nothing failed */
            break;
        }
    }
    CU_ASSERT(n > 1);
}

void
xqc_test_qpack_enc_ins_alloc_failures(void)
{
    xqc_http_header_t hdr[] = {
        /* Insert with Literal Name */
        {
            .name   = {.iov_base = "x-literal", .iov_len = 9},
            .value  = {.iov_base = "inserted", .iov_len = 8},
        },
        /* Insert with Name Reference, to the static table */
        {
            .name   = {.iov_base = "content-type", .iov_len = 12},
            .value  = {.iov_base = "text/inserted", .iov_len = 13},
        },
        /* Insert with Name Reference, to the dynamic table */
        {
            .name   = {.iov_base = "f01", .iov_len = 3},
            .value  = {.iov_base = "inserted", .iov_len = 8},
        },
        /* Insert with Literal Name, of the name only */
        {
            .name   = {.iov_base = "x-name-only", .iov_len = 11},
            .value  = {.iov_base = "never indexed", .iov_len = 13},
            .flags  = XQC_HTTP_HEADER_FLAG_NEVER_INDEX_VALUE,
        },
        /* Duplicate */
        g_qpack_test_draining,
    };
    xqc_engine_t *engine = test_create_engine();
    size_t i;

    CU_ASSERT_FATAL(engine != NULL);
    for (i = 0; i < sizeof(hdr) / sizeof(hdr[0]); i++) {
        xqc_qpack_test_enc_ins_sweep(engine, &hdr[i], XQC_FALSE);
    }
#ifdef XQC_COMPAT_DUPLICATE
    /* Duplicate, with the copy of xqc_dtable_duplicate_compat() */
    xqc_qpack_test_enc_ins_sweep(engine, &g_qpack_test_draining, XQC_TRUE);
#endif
    xqc_engine_destroy(engine);
}

/*
 * A client engine with the h3 ALPN. The allocations that its connections
 * make to create their h3 connection, up to and including the QPACK
 * context, are counted from the h3 ALPN's conn_create_notify, with the
 * heap dirtied first, to the application's h3_conn_create_notify; the one
 * numbered g_qpack_test_h3c_fail_at fails.
 */
static long g_qpack_test_h3c_fail_at;
static int  g_qpack_test_h3c_created;

static ssize_t
xqc_qpack_test_h3c_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data)
{
    return size;
}

static void
xqc_qpack_test_h3c_set_timer(xqc_msec_t wake_after, void *user_data)
{
}

static int
xqc_qpack_test_h3c_create_notify(xqc_h3_conn_t *h3_conn,
    const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_test_alloc_count = -1;
    g_qpack_test_h3c_created++;
    return 0;
}

static int
xqc_qpack_test_h3c_conn_create_notify(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *conn_user_data, void *conn_proto_data)
{
    int ret;

    xqc_qpack_test_dirty_heap();
    xqc_test_alloc_failed = 0;
    xqc_test_alloc_fail_at = g_qpack_test_h3c_fail_at;
    xqc_test_alloc_count = 0;
    ret = h3_conn_callbacks.conn_create_notify(conn, cid, conn_user_data,
                                               conn_proto_data);
    xqc_test_alloc_count = -1;
    return ret;
}

static xqc_engine_t *
xqc_qpack_test_h3c_engine(void)
{
    xqc_engine_t               *engine;
    xqc_h3_callbacks_t          h3_cbs;
    xqc_app_proto_callbacks_t   ap_cbs;
    xqc_engine_ssl_config_t     ssl;
    xqc_engine_callback_t       cb = {
        .log_callbacks = xqc_null_log_cb,
        .set_event_timer = xqc_qpack_test_h3c_set_timer,
    };
    xqc_transport_callbacks_t   tcbs = {
        .write_socket = xqc_qpack_test_h3c_write,
    };

    memset(&ssl, 0, sizeof(ssl));
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;
    engine = xqc_engine_create(XQC_ENGINE_CLIENT, NULL, &ssl, &cb, &tcbs,
                               NULL);
    CU_ASSERT_FATAL(engine != NULL);

    memset(&h3_cbs, 0, sizeof(h3_cbs));
    h3_cbs.h3c_cbs.h3_conn_create_notify = xqc_qpack_test_h3c_create_notify;
    CU_ASSERT_FATAL(xqc_h3_ctx_init(engine, &h3_cbs) == XQC_OK);

    memset(&ap_cbs, 0, sizeof(ap_cbs));
    ap_cbs.conn_cbs = h3_conn_callbacks;
    ap_cbs.conn_cbs.conn_create_notify = xqc_qpack_test_h3c_conn_create_notify;
    ap_cbs.stream_cbs = h3_stream_callbacks;
    CU_ASSERT_FATAL(xqc_engine_register_alpn(engine, XQC_ALPN_H3,
        strlen(XQC_ALPN_H3), &ap_cbs,
        xqc_engine_get_alpn_ctx(engine, XQC_ALPN_H3, strlen(XQC_ALPN_H3)))
        == XQC_OK);
    return engine;
}

static const xqc_cid_t *
xqc_qpack_test_h3c_connect(xqc_engine_t *engine)
{
    xqc_conn_settings_t         settings;
    xqc_conn_ssl_config_t       conn_ssl;
    struct sockaddr_in          peer;

    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    memset(&conn_ssl, 0, sizeof(conn_ssl));
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_qpack_test_h3c_created = 0;
    return xqc_h3_connect(engine, &settings, NULL, 0, "", 0, &conn_ssl,
                          (struct sockaddr *)&peer, sizeof(peer), NULL);
}

/*
 * Each allocation that xqc_qpack_create() makes fails in turn
 * (xqc_alloc_wrap.h), with the heap dirtied first: the creation fails, and
 * it frees what it allocated, with nothing else. The sweep ends with a run
 * in which nothing fails and the QPACK handler is created.
 */
void
xqc_test_qpack_create_alloc_failures(void)
{
    long            n;
    xqc_qpack_t    *qpk;
    xqc_engine_t   *engine = xqc_qpack_test_h3c_engine();
    xqc_ins_buf_t   ins_buf = { NULL, NULL };

    CU_ASSERT_FATAL(engine != NULL);

    for (n = 1; n < 1000; n++) {
        xqc_qpack_test_dirty_heap();
        xqc_test_alloc_live = 0;
        xqc_test_alloc_tracking = 1;
        xqc_test_alloc_failed = 0;
        xqc_test_alloc_fail_at = n;
        xqc_test_alloc_count = 0;
        qpk = xqc_qpack_create(16 * 1024, 16 * 1024, engine->log, &ins_cb,
                               &ins_buf);
        xqc_test_alloc_count = -1;
        CU_ASSERT((qpk == NULL) == xqc_test_alloc_failed);
        xqc_qpack_destroy(qpk);
        xqc_test_alloc_tracking = 0;
        CU_ASSERT(xqc_test_alloc_live == 0);

        if (!xqc_test_alloc_failed) {
            /* nothing failed: the QPACK handler was created */
            break;
        }
    }
    CU_ASSERT(n > 1);

    xqc_engine_destroy(engine);
}


/*
 * Each allocation that an h3 client connection makes to create its h3
 * connection, up to and including its QPACK context, fails in turn: the
 * h3 connection is not created, xqc_h3_connect() fails, and once the
 * engine is destroyed nothing allocated since it was created is left.
 * The sweep ends with a run in which nothing fails and the h3 connection
 * is created.
 */
void
xqc_test_qpack_h3_conn_create_alloc_failures(void)
{
    long                n;
    int                 failed;
    const xqc_cid_t    *cid;
    xqc_engine_t       *engine;

    /* the first run makes the allocations made once per process */
    g_qpack_test_h3c_fail_at = 0;
    engine = xqc_qpack_test_h3c_engine();
    CU_ASSERT_FATAL(xqc_qpack_test_h3c_connect(engine) != NULL);
    xqc_engine_destroy(engine);

    for (n = 1; n < 1000; n++) {
        xqc_test_alloc_live = 0;
        xqc_test_alloc_tracking = 1;
        engine = xqc_qpack_test_h3c_engine();
        g_qpack_test_h3c_fail_at = n;
        cid = xqc_qpack_test_h3c_connect(engine);
        g_qpack_test_h3c_fail_at = 0;
        failed = xqc_test_alloc_failed;
        CU_ASSERT((cid == NULL) == failed);
        CU_ASSERT(g_qpack_test_h3c_created == !failed);
        xqc_engine_destroy(engine);
        xqc_test_alloc_tracking = 0;
        CU_ASSERT(xqc_test_alloc_live == 0);

        if (!failed) {
            /* nothing failed: the h3 connection was created */
            break;
        }
    }
    CU_ASSERT(n > 1);
}

#else

void
xqc_test_qpack_enc_ins_alloc_failures(void)
{
    /* needs the linker's --wrap (see tests/CMakeLists.txt) */
}

void
xqc_test_qpack_create_alloc_failures(void)
{
    /* needs the linker's --wrap (see tests/CMakeLists.txt) */
}

void
xqc_test_qpack_h3_conn_create_alloc_failures(void)
{
    /* needs the linker's --wrap (see tests/CMakeLists.txt) */
}

#endif
