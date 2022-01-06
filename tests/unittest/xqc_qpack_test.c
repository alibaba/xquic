/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_qpack_test.h"
#include "src/http3/xqc_h3_header.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/qpack/xqc_qpack.h"
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>

#include "tests/unittest/xqc_common_test.h"

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

    xqc_qpack_t *qpk_client = xqc_qpack_create(16384, engine->log, &ins_cb, &ins_buf_client);
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
    xqc_qpack_t *qpk_server = xqc_qpack_create(16384, engine->log, &ins_cb, &ins_buf_server);

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
    read = xqc_qpack_dec_headers(qpk_server, req_ctx, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out, 1, &blocked);
    CU_ASSERT(read > 0 && blocked == XQC_TRUE);
    efs_buf_client->consumed_len += read;

    /* try again will do nothing */
    read = xqc_qpack_dec_headers(qpk_server, req_ctx, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out, 1, &blocked);
    CU_ASSERT(read == 0 && blocked == XQC_TRUE);
    efs_buf_client->consumed_len += read;


    /* decode stream 1, shall not be blocked */
    xqc_bool_t blocked2 = XQC_FALSE;
    void *req_ctx2 = xqc_qpack_create_req_ctx(1);
    read = xqc_qpack_dec_headers(qpk_server, req_ctx2, efs_buf_server->data + efs_buf_server->consumed_len, efs_buf_server->data_len - efs_buf_server->consumed_len, &hdrs_out2, 1, &blocked);
    CU_ASSERT(read == efs_buf_server->data_len && blocked2 == XQC_FALSE);
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
    read = xqc_qpack_dec_headers(qpk_server, req_ctx, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out, 1, &blocked);
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

    // xqc_qpack_t *qpk_client = xqc_qpack_create(&ins_cb, &buf_client, engine->log, 512);
    xqc_qpack_t *qpk_client = xqc_qpack_create(512, engine->log, &ins_cb, &buf_client);

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
    // xqc_qpack_t *qpk_server = xqc_qpack_create(&ins_cb, &buf_server, engine->log, 512);
    xqc_qpack_t *qpk_server = xqc_qpack_create(512, engine->log, &ins_cb, &buf_server);

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
    read = xqc_qpack_dec_headers(qpk_server, req_ctx_0, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out, 1, &blocked);
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
    read = xqc_qpack_dec_headers(qpk_server, req_ctx_1, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out_draining, 1,
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



const unsigned char chars[63] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
void
xqc_gen_rand_str(char *dst, size_t len)
{
    srandom(time(NULL));
    for (size_t i = 0; i < len; i++) {
        dst[i] = chars[random() & 63];
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

    // xqc_qpack_t *qpk_client = xqc_qpack_create(&ins_cb, &buf_client, engine->log, 512);
    xqc_qpack_t *qpk_client = xqc_qpack_create(16*1024, engine->log, &ins_cb, &buf_client);

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
    // xqc_qpack_t *qpk_server = xqc_qpack_create(&ins_cb, &buf_server, engine->log, 512);
    xqc_qpack_t *qpk_server = xqc_qpack_create(16*1024, engine->log, &ins_cb, &buf_server);

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
    ret = xqc_qpack_dec_headers(qpk_server, req_ctx_0, efs_buf_client->data + efs_buf_client->consumed_len, efs_buf_client->data_len - efs_buf_client->consumed_len, &hdrs_out, 1, &blocked);
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

    xqc_qpack_t *qpk_client = xqc_qpack_create(16384, engine->log, &ins_cb, &ins_buf_client);
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
    xqc_qpack_t *qpk_server = xqc_qpack_create(16384, engine->log, &ins_cb, &ins_buf_server);
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
    processed = xqc_qpack_dec_headers(qpk_server, rep_ctx1, efs_buf_client->data, efs_buf_client->data_len, &hdrs_out, XQC_TRUE, &blocked);
    CU_ASSERT(processed == efs_buf_client->data_len);


    xqc_rep_ctx_t *rep_ctx2 = xqc_qpack_create_req_ctx(4);
    processed = xqc_qpack_dec_headers(qpk_server, rep_ctx2, efs_buf_client2->data, efs_buf_client2->data_len, &hdrs_out2, XQC_TRUE, &blocked);
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



void
xqc_qpack_test()
{
    xqc_qpack_test_basic();
    xqc_qpack_test_duplicate();
    xqc_qpack_test_robust();
    xqc_test_min_ref();
}
