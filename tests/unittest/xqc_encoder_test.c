/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_encoder_test.h"
#include "src/http3/qpack/xqc_encoder.h"
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>

#include "tests/unittest/xqc_common_test.h"

#define XQC_TEST_ENCODER_MAX_HEADERS 128

void
xqc_test_encoder_basic()
{
    xqc_int_t ret = XQC_OK;
    xqc_var_buf_t *efs_buf = xqc_var_buf_create(4096);
    xqc_var_buf_t *ins_buf = xqc_var_buf_create(4096);

    xqc_http_header_t header[XQC_TEST_ENCODER_MAX_HEADERS] = {
        {
            .name   = {.iov_base = ":method", .iov_len = 7},
            .value  = {.iov_base = "POST", .iov_len = 4},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = ":scheme", .iov_len = 7},
            .value  = {.iov_base = "https", .iov_len = 5},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "host", .iov_len = 4},
            .value  = {.iov_base = "test.xquic.com.cn", .iov_len = 17},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = ":path", .iov_len = 5},
            .value  = {.iov_base = "/xquic/test/encoder/", .iov_len = 20},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "content-type", .iov_len = 12},
            .value  = {.iov_base = "text/plain", .iov_len = 10},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "content-length", .iov_len = 14},
            .value  = {.iov_base = "10245", .iov_len = 5},
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
            .name   = {.iov_base = ":authorization", .iov_len = 14},
            .value  = {.iov_base = "XXFJIOFD03N43O9VD8NFE9W3SJV990E3", .iov_len = 32},
            .flags  = XQC_HTTP_HEADER_FLAG_NEVER_INDEX_VALUE
        },
        {
            .name   = {.iov_base = "cookie", .iov_len = 19},
            .value  = {.iov_base = "this_is_a_cookie_buf_pretending_to_be_long", .iov_len = 2500},  /* fake length */
            .flags  = XQC_HTTP_HEADER_FLAG_NEVER_INDEX_VALUE
        }
    };

    xqc_http_headers_t hdrs = {
        header, 10, XQC_TEST_ENCODER_MAX_HEADERS
    };

    xqc_engine_t *engine = test_create_engine();


    xqc_encoder_t *enc = xqc_encoder_create(engine->log);
    CU_ASSERT(enc != NULL);

    /* encode when dtable capacity is 0, no encoder instructions shall be generated */
    ret = xqc_encoder_enc_headers(enc, efs_buf, ins_buf, 0, &hdrs);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(efs_buf->data_len > 0 && ins_buf->data_len == 0);


    ret = xqc_encoder_set_max_dtable_cap(enc, 16 * 32);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_encoder_set_max_dtable_cap(enc, 64 * 32);
    CU_ASSERT(ret != XQC_OK);

    /* set capacity */
    ret = xqc_encoder_set_dtable_cap(enc, 16 * 1024);
    CU_ASSERT(ret == XQC_OK);


    /* encode when max blocked stream is 0 */
    ret = xqc_encoder_enc_headers(enc, efs_buf, ins_buf, 0, &hdrs);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(efs_buf->data_len > 0 && ins_buf->data_len == 0);

    ret = xqc_encoder_set_max_blocked_stream(enc, 64);
    CU_ASSERT(ret == XQC_OK);

    /* encode while max blocked stream is not 0 */
    ret = xqc_encoder_enc_headers(enc, efs_buf, ins_buf, 0, &hdrs);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(efs_buf->data_len > 0 && ins_buf->data_len > 0);

    xqc_var_buf_free(efs_buf);
    xqc_var_buf_free(ins_buf);
    xqc_encoder_destroy(enc);
    xqc_engine_destroy(engine);
}


void
xqc_test_insert_name_limit()
{
    xqc_int_t ret = XQC_OK;
    xqc_var_buf_t *efs_buf = xqc_var_buf_create(4096);
    xqc_var_buf_t *ins_buf = xqc_var_buf_create(4096);

    xqc_http_header_t header[XQC_TEST_ENCODER_MAX_HEADERS] = {
        {
            .name   = {.iov_base = "insert_name_limit_pretending_to_be_long", .iov_len = 66},
            .value  = {.iov_base = "value", .iov_len = 5},    /* fake length */
        }
    };

    xqc_http_headers_t hdrs = {
        header, 1, XQC_TEST_ENCODER_MAX_HEADERS
    };

    xqc_engine_t *engine = test_create_engine();

    xqc_encoder_t *enc = xqc_encoder_create(engine->log);
    CU_ASSERT(enc != NULL);

    ret = xqc_encoder_set_max_dtable_cap(enc, 1024);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_encoder_set_dtable_cap(enc, 1024);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_encoder_set_max_blocked_stream(enc, 64);
    CU_ASSERT(ret == XQC_OK);

    /* name is too long, exceed cap / 16 = 64 bytes */
    ret = xqc_encoder_enc_headers(enc, efs_buf, ins_buf, 0, &hdrs);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(efs_buf->data_len > 0 && ins_buf->data_len == 0);

    /* increase name upper limit */
    xqc_var_buf_clear(efs_buf);
    xqc_var_buf_clear(ins_buf);
    xqc_encoder_set_insert_limit(enc, 0.5, 0.75);
    ret = xqc_encoder_enc_headers(enc, efs_buf, ins_buf, 0, &hdrs);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(efs_buf->data_len > 0 && ins_buf->data_len != 0);

    xqc_var_buf_free(efs_buf);
    xqc_var_buf_free(ins_buf);

    xqc_encoder_destroy(enc);
    xqc_engine_destroy(engine);

}


void
xqc_test_insert_entry_limit()
{
    xqc_int_t ret = XQC_OK;
    xqc_var_buf_t *efs_buf = xqc_var_buf_create(4096);
    xqc_var_buf_t *ins_buf = xqc_var_buf_create(4096);

    xqc_http_header_t header[XQC_TEST_ENCODER_MAX_HEADERS] = {
        {
            .name   = {.iov_base = "insert_limit", .iov_len = 12},
            .value  = {.iov_base = "this_is_a_insert_nv_pretending_to_be_long", .iov_len = 888},    /* fake length */
        }
    };

    xqc_http_headers_t hdrs = {
        header, 1, XQC_TEST_ENCODER_MAX_HEADERS
    };

    xqc_engine_t *engine = test_create_engine();


    xqc_encoder_t *enc = xqc_encoder_create(engine->log);
    CU_ASSERT(enc != NULL);

    ret = xqc_encoder_set_max_dtable_cap(enc, 1024);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_encoder_set_dtable_cap(enc, 1024);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_encoder_set_max_blocked_stream(enc, 64);

    /* value is too long, name shall be inserted */
    ret = xqc_encoder_enc_headers(enc, efs_buf, ins_buf, 0, &hdrs);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(efs_buf->data_len > 0 && ins_buf->data_len != 0);

    /* increase name upper limit, name-value shall be inserted again */
    xqc_encoder_set_insert_limit(enc, 0.5, 1);
    ret = xqc_encoder_enc_headers(enc, efs_buf, ins_buf, 0, &hdrs);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(efs_buf->data_len > 0 && ins_buf->data_len != 0);

    xqc_var_buf_free(efs_buf);
    xqc_var_buf_free(ins_buf);

    xqc_encoder_destroy(enc);
    xqc_engine_destroy(engine);

}


void
xqc_test_encoder()
{
    xqc_test_encoder_basic();
    xqc_test_insert_entry_limit();
    xqc_test_insert_name_limit();
}

