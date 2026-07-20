/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <inttypes.h>
#include "xqc_prefixed_str_test.h"
#include "tests/unittest/xqc_common_test.h"
#include "src/http3/qpack/xqc_prefixed_str.h"
#include "src/http3/xqc_h3_defs.h"
#include "src/common/utils/var_buf/xqc_var_buf.h"

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
        pstr = xqc_prefixed_str_pctx_create(256, XQC_H3_MAX_FIELD_SECTION_SIZE);
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
            pstr = xqc_prefixed_str_pctx_create(256, XQC_H3_MAX_FIELD_SECTION_SIZE);
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


/**
 * Test that xqc_prefixed_str_pctx_create enforces max_str_len limit
 * (CVE: QPACK Huffman decoder unbounded pre-allocation)
 */
void
test_prefixed_str_limit()
{
    xqc_prefixed_str_t *pstr = NULL;
    ssize_t read;
    int fin = 0;

    /*
     * Test 1: non-Huffman declared length exceeds max_str_len.
     * For n=7, non-Huffman, declared length = 40000 > 32768.
     * byte[0] = 0x7F (Huffman=0, prefix=127 -> overflow)
     * (40000 - 127) = 39873 in variable-length: {0xC1, 0xB7, 0x02}
     * byte[4] = 0x00 (data byte to trigger value stage)
     */
    uint8_t non_huff_input[] = {0x7F, 0xC1, 0xB7, 0x02, 0x00};

    pstr = xqc_prefixed_str_pctx_create(256, XQC_H3_MAX_FIELD_SECTION_SIZE);
    CU_ASSERT(pstr != NULL);
    xqc_prefixed_str_init(pstr, 7);

    read = xqc_parse_prefixed_str(pstr, non_huff_input, sizeof(non_huff_input), &fin);
    CU_ASSERT(read == -QPACK_DECOMPRESSION_FAILED);
    CU_ASSERT(fin == 0);

    xqc_prefixed_str_free(pstr);
    pstr = NULL;

    /*
     * Test 2: Huffman declared length exceeds 2 * max_str_len.
     * For n=7, Huffman=1, declared length = 65537 > 65536.
     * byte[0] = 0xFF (Huffman=1, prefix=127 -> overflow)
     * (65537 - 127) = 65410 in variable-length: {0x82, 0xFF, 0x03}
     * byte[4] = 0x00 (data byte to trigger value stage)
     */
    uint8_t huff_input[] = {0xFF, 0x82, 0xFF, 0x03, 0x00};

    pstr = xqc_prefixed_str_pctx_create(256, XQC_H3_MAX_FIELD_SECTION_SIZE);
    CU_ASSERT(pstr != NULL);
    xqc_prefixed_str_init(pstr, 7);

    read = xqc_parse_prefixed_str(pstr, huff_input, sizeof(huff_input), &fin);
    CU_ASSERT(read == -QPACK_DECOMPRESSION_FAILED);
    CU_ASSERT(fin == 0);

    xqc_prefixed_str_free(pstr);
    pstr = NULL;

    /*
     * Test 3: Boundary - Huffman declared length = 2 * max_str_len should pass
     * the length check and be decoded incrementally without unbounded allocation.
     * declared length = 65536, encoded as n=7 Huffman:
     * byte[0] = 0xFF, (65536 - 127) = 65409 in variable-length: {0x81, 0xFF, 0x03}
     */
    uint8_t boundary_input[] = {0xFF, 0x81, 0xFF, 0x03, 0x00};

    pstr = xqc_prefixed_str_pctx_create(256, XQC_H3_MAX_FIELD_SECTION_SIZE);
    CU_ASSERT(pstr != NULL);
    xqc_prefixed_str_init(pstr, 7);

    read = xqc_parse_prefixed_str(pstr, boundary_input, sizeof(boundary_input), &fin);
    CU_ASSERT(read != -QPACK_DECOMPRESSION_FAILED);

    xqc_prefixed_str_free(pstr);
    pstr = NULL;
}

/**
 * Test max_str_len boundary conditions for both non-Huffman and Huffman
 * string literals, including incremental decoding of large Huffman strings.
 */
void
test_prefixed_str_limit_boundary()
{
    xqc_prefixed_str_t *pstr = NULL;
    ssize_t read;
    int fin = 0;
    uint64_t max_len = XQC_H3_MAX_FIELD_SECTION_SIZE;
    xqc_int_t ret;

    /*
     * Test 1: non-Huffman declared length = max_str_len should pass
     * the length check. n=7, non-Huffman, length = 32768,
     * encoded as {0x7F, 0x81, 0xFF, 0x01}.
     */
    uint8_t non_huff_max[] = {0x7F, 0x81, 0xFF, 0x01, 0x00};
    pstr = xqc_prefixed_str_pctx_create(256, max_len);
    CU_ASSERT(pstr != NULL);
    xqc_prefixed_str_init(pstr, 7);
    read = xqc_parse_prefixed_str(pstr, non_huff_max, sizeof(non_huff_max), &fin);
    CU_ASSERT(read != -QPACK_DECOMPRESSION_FAILED);
    xqc_prefixed_str_free(pstr);
    pstr = NULL;

    /*
     * Test 2: non-Huffman declared length = max_str_len + 1 should be rejected.
     * n=7, non-Huffman, length = 32769,
     * encoded as {0x7F, 0x82, 0xFF, 0x01}.
     */
    uint8_t non_huff_over[] = {0x7F, 0x82, 0xFF, 0x01, 0x00};
    pstr = xqc_prefixed_str_pctx_create(256, max_len);
    CU_ASSERT(pstr != NULL);
    xqc_prefixed_str_init(pstr, 7);
    read = xqc_parse_prefixed_str(pstr, non_huff_over, sizeof(non_huff_over), &fin);
    CU_ASSERT(read == -QPACK_DECOMPRESSION_FAILED);
    xqc_prefixed_str_free(pstr);
    pstr = NULL;

    /* Prepare raw data and Huffman-encoded strings of 'a'. */
    uint8_t raw[32769];
    memset(raw, 'a', sizeof(raw));

    xqc_var_buf_t *enc_buf_max = xqc_var_buf_create(max_len);
    xqc_var_buf_t *enc_buf_over = xqc_var_buf_create(max_len + 1);
    CU_ASSERT(enc_buf_max != NULL && enc_buf_over != NULL);

    enc_buf_max->data[0] = 0;
    ret = xqc_write_prefixed_str(enc_buf_max, raw, max_len, 7);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(enc_buf_max->data_len > 0);
    CU_ASSERT(enc_buf_max->data[0] & 0x80); /* Huffman flag must be set */

    enc_buf_over->data[0] = 0;
    ret = xqc_write_prefixed_str(enc_buf_over, raw, max_len + 1, 7);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(enc_buf_over->data_len > 0);
    CU_ASSERT(enc_buf_over->data[0] & 0x80); /* Huffman flag must be set */

    /*
     * Test 3: Huffman decoded output = max_str_len should succeed.
     */
    pstr = xqc_prefixed_str_pctx_create(256, max_len);
    CU_ASSERT(pstr != NULL);
    xqc_prefixed_str_init(pstr, 7);
    fin = 0;
    read = xqc_parse_prefixed_str(pstr, enc_buf_max->data, enc_buf_max->data_len, &fin);
    CU_ASSERT(read == enc_buf_max->data_len);
    CU_ASSERT(fin == 1);
    CU_ASSERT(pstr->value->data_len == max_len);
    xqc_prefixed_str_free(pstr);
    pstr = NULL;

    /*
     * Test 4: Huffman decoded output = max_str_len + 1 should be rejected
     * by the post-decode length check.
     */
    pstr = xqc_prefixed_str_pctx_create(256, max_len);
    CU_ASSERT(pstr != NULL);
    xqc_prefixed_str_init(pstr, 7);
    fin = 0;
    read = xqc_parse_prefixed_str(pstr, enc_buf_over->data, enc_buf_over->data_len, &fin);
    CU_ASSERT(read == -QPACK_DECOMPRESSION_FAILED);
    xqc_prefixed_str_free(pstr);
    pstr = NULL;

    /*
     * Test 5: incremental decode of a large Huffman string should succeed
     * without unbounded allocation.
     */
    pstr = xqc_prefixed_str_pctx_create(256, max_len);
    CU_ASSERT(pstr != NULL);
    xqc_prefixed_str_init(pstr, 7);
    fin = 0;
    ssize_t total = 0;
    size_t chunk = 100;
    size_t off = 0;
    while (off < enc_buf_max->data_len) {
        size_t len = (off + chunk > enc_buf_max->data_len)
                         ? (enc_buf_max->data_len - off) : chunk;
        read = xqc_parse_prefixed_str(pstr, enc_buf_max->data + off, len, &fin);
        CU_ASSERT(read != -QPACK_DECOMPRESSION_FAILED);
        total += read;
        off += read;
    }
    CU_ASSERT(total == enc_buf_max->data_len);
    CU_ASSERT(fin == 1);
    CU_ASSERT(pstr->value->data_len == max_len);
    xqc_prefixed_str_free(pstr);
    pstr = NULL;

    xqc_var_buf_free(enc_buf_max);
    xqc_var_buf_free(enc_buf_over);
}

void
xqc_test_prefixed_str()
{
    test_prefixed_str_basic();
    test_prefixed_str_len();
    test_prefixed_str_limit();
    test_prefixed_str_limit_boundary();
}
