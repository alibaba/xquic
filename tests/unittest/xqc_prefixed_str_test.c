/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <inttypes.h>
#include "xqc_prefixed_str_test.h"
#include "tests/unittest/xqc_common_test.h"
#include "src/http3/qpack/xqc_prefixed_str.h"

void
test_prefixed_str_basic()
{
    size_t i, j;
    size_t len;
    int fin;
    uint8_t raw[256], ebuf[4096], dbuf[4096];
    uint8_t *end;
    xqc_prefixed_str_t *pstr = NULL;
    ssize_t nwrite = 0, read, consumed;
    xqc_int_t ret = XQC_OK;

    xqc_var_buf_t *enc_buf = xqc_var_buf_create(8192);

    srandom(time(NULL));


    for (i = 0; i < 10000; i++) {
        /* generate random n */
        uint8_t n = random() & 7;
        if (n == 0) {
            n = 1;
        }

        /* generate random buffer with random length */
        len = (random() & 255) + 1;
        for (j = 0; j < len; ++j) {
            raw[j] = (uint8_t)round(((double)random() / RAND_MAX * 255));
        }

        /* write prefixed string */
        enc_buf->data[0] = 0;
        ret = xqc_write_prefixed_str(enc_buf, raw, len, n);
        CU_ASSERT(ret == XQC_OK);
        CU_ASSERT(enc_buf->data_len > 0);

        /* create prefixed string context */
        pstr = xqc_prefixed_str_pctx_create(256);
        xqc_prefixed_str_init(pstr, n);
        CU_ASSERT(pstr != NULL);
        fin  = 0;

        /* decode prefixed string byte by byte */
        read = xqc_parse_prefixed_str(pstr, enc_buf->data, enc_buf->data_len, &fin);
        CU_ASSERT(fin == 1);
        CU_ASSERT(read == enc_buf->data_len);
        CU_ASSERT(pstr->value->data_len == len);
        CU_ASSERT(memcmp(raw, pstr->value->data, len) == 0);

        xqc_prefixed_str_free(pstr);
        pstr = NULL;
        xqc_var_buf_clear(enc_buf);
    }

    xqc_var_buf_free(enc_buf);
}


void
test_prefixed_str_len()
{
    size_t i, j;
    size_t len;
    int fin;
    uint8_t raw[4096], ebuf[4096], dbuf[4096];
    uint8_t *end;
    xqc_prefixed_str_t *pstr = NULL;
    ssize_t nwrite = 0, read, consumed;
    xqc_int_t ret = XQC_OK;

    xqc_var_buf_t *enc_buf = xqc_var_buf_create(8192);

    srandom(time(NULL));


    for (i = 0; i < 1000; i++) {
        len = i;
        /* generate random n */
        for (uint8_t n = 1; n <= 8; n++) {
            /* generate random buffer with random length */
            for (j = 0; j < len; ++j) {
                raw[j] = (uint8_t) round(((double) random() / RAND_MAX * 255));
            }

            /* write prefixed string */
            enc_buf->data[0] = 0;
            ret = xqc_write_prefixed_str(enc_buf, raw, len, n);
            CU_ASSERT(ret == XQC_OK);
            CU_ASSERT(enc_buf->data_len > 0);

            /* create prefixed string context */
            pstr = xqc_prefixed_str_pctx_create(256);
            xqc_prefixed_str_init(pstr, n);
            CU_ASSERT(pstr != NULL);
            fin = 0;

            /* decode prefixed string byte by byte */
            read = xqc_parse_prefixed_str(pstr, enc_buf->data, enc_buf->data_len, &fin);
            CU_ASSERT(fin == 1);
            CU_ASSERT(read == enc_buf->data_len);
            CU_ASSERT(pstr->value->data_len == len);
            CU_ASSERT(memcmp(raw, pstr->value->data, len) == 0);

            xqc_prefixed_str_free(pstr);
            pstr = NULL;
            xqc_var_buf_clear(enc_buf);
        }
    }

    xqc_var_buf_free(enc_buf);
}


void
xqc_test_prefixed_str()
{
    test_prefixed_str_basic();
    test_prefixed_str_len();
}

