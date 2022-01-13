/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_stable_test.h"
#include "src/http3/qpack/stable/xqc_stable.h"
#include <inttypes.h>

typedef struct xqc_stable_entry_s {
    /* name-value pair */
    xqc_nv_t            nv;

    /* header type */
    xqc_hdr_type_t      type;

    /* 
     * :status/access-control-allow-headers headers are not continuously
     * distributed in static table. when lookup these two headers, if name
     * matched while value not, this attribute is set to tell the next 
     * entry with the same name in static table 
     */
    uint64_t            hop;

} xqc_stable_entry_t;


void 
xqc_test_static_table_lookup_basic()
{
    xqc_hdr_type_t htype = XQC_HDR_UNKNOWN;
    xqc_nv_ref_type_t match;
    uint64_t idx;
    xqc_nv_t nv[3] = {
        {
            .name   = {.data = ":method", .len = 7},
            .value  = {.data = "POST", .len = 4},
        },
        {
            .name   = {.data = "content-length", .len = 14},
            .value  = {.data = "1000", .len = 4},
        },
        {
            .name   = {.data = "host", .len = 4},
            .value  = {.data = "test.xquic.com", .len = 14},
        },
    };

    htype = xqc_h3_hdr_type(nv[0].name.data, nv[0].name.len);
    CU_ASSERT(htype == XQC_HDR__METHOD);
    match = xqc_stable_lookup(nv[0].name.data, nv[0].name.len, nv[0].value.data, 
                              nv[0].value.len, htype, &idx);
    CU_ASSERT(match == XQC_NV_REF_NAME_AND_VALUE && idx == 20);

    htype = xqc_h3_hdr_type(nv[1].name.data, nv[1].name.len);
    CU_ASSERT(htype == XQC_HDR_CONTENT_LENGTH);
    match = xqc_stable_lookup(nv[1].name.data, nv[1].name.len, nv[1].value.data, 
                              nv[1].value.len, htype, &idx);
    CU_ASSERT(match == XQC_NV_REF_NAME && idx == 4);

    htype = xqc_h3_hdr_type(nv[2].name.data, nv[2].name.len);
    CU_ASSERT(htype == XQC_HDR_UNKNOWN);
    match = xqc_stable_lookup(nv[2].name.data, nv[2].name.len, nv[2].value.data, 
                              nv[2].value.len, htype, &idx);
    CU_ASSERT(match == XQC_NV_REF_NONE);

    /* 
     * chect static table will get an error result,  which is thought to be 
     * the responsibility of user 
     */
    htype = XQC_HDR__METHOD;
    match = xqc_stable_lookup("this is a test header name which is incredibly very very very very "
                              "very long", 71, "this is a test header value which is incredibly "
                              "very very very very very long", 77, htype, &idx);
    CU_ASSERT(match == XQC_NV_REF_NAME);

}

void
xqc_test_static_table_lookup_robust()
{
    xqc_hdr_type_t htype = XQC_HDR_UNKNOWN;
    xqc_nv_ref_type_t match;
    uint64_t idx;

    htype = xqc_h3_hdr_type(":authority", 10);
    match = xqc_stable_lookup(":authority", 10, "", 0, htype, &idx);
    CU_ASSERT(match == XQC_NV_REF_NAME_AND_VALUE && idx == 0 && htype == XQC_HDR__AUTHORITY);

    htype = xqc_h3_hdr_type(":authority", 10);
    match = xqc_stable_lookup(":authority", 10, NULL, 0, htype, &idx);
    CU_ASSERT(match == XQC_NV_REF_NAME_AND_VALUE && idx == 0 && htype == XQC_HDR__AUTHORITY);


    htype = xqc_h3_hdr_type(NULL, 0);
    match = xqc_stable_lookup(NULL, 0, "200", 3, htype, &idx);
    CU_ASSERT(match == XQC_NV_REF_NONE);
}


extern xqc_stable_entry_t xqc_g_static_table[99];

void
xqc_test_static_table_lookup_nv_matched()
{
    xqc_hdr_type_t htype = XQC_HDR_UNKNOWN;
    xqc_nv_ref_type_t match;
    uint64_t idx;

    xqc_stable_entry_t *entry = xqc_g_static_table;
    for (size_t i = 0; i < 99; i++) {
        htype = xqc_h3_hdr_type(entry->nv.name.data, entry->nv.name.len);
        match = xqc_stable_lookup(entry->nv.name.data, entry->nv.name.len, entry->nv.value.data,
                                  entry->nv.value.len, htype, &idx);
        CU_ASSERT(match == XQC_NV_REF_NAME_AND_VALUE && idx == i && htype == entry->type);
        entry++;
    }
}

void
xqc_test_static_table_lookup_name_matched()
{
    xqc_hdr_type_t htype = XQC_HDR_UNKNOWN;
    xqc_nv_ref_type_t match;
    uint64_t idx;

    xqc_stable_entry_t *entry = xqc_g_static_table;
    for (size_t i = 0; i < 99; i++) {
        htype = xqc_h3_hdr_type(entry->nv.name.data, entry->nv.name.len);
        match = xqc_stable_lookup(entry->nv.name.data, entry->nv.name.len, "test_value", 10,
                                  htype, &idx);
        CU_ASSERT(match == XQC_NV_REF_NAME && htype == entry->type);
        entry++;
    }
}

void
xqc_test_static_table_get_nv_basic()
{
    xqc_var_buf_t *name_buf = xqc_var_buf_create(1024);
    xqc_var_buf_t *value_buf = xqc_var_buf_create(1024);
    xqc_int_t ret = XQC_OK;
    xqc_stable_entry_t *entry = xqc_g_static_table;

    for (uint64_t i = 0; i < 99; i++) {
        xqc_var_buf_clear(name_buf);
        xqc_var_buf_clear(value_buf);
        ret = xqc_stable_get_nv(i, name_buf, value_buf);
        CU_ASSERT(ret == XQC_OK && strcmp(name_buf->data, entry->nv.name.data) == 0
                  && strcmp(value_buf->data, entry->nv.value.data) == 0);
        entry++;
    }
    xqc_var_buf_free(name_buf);
    xqc_var_buf_free(value_buf);
}

void
xqc_test_static_table_get_nv_robust()
{
    xqc_var_buf_t *nbuf = xqc_var_buf_create(4096);
    xqc_var_buf_t *vbuf = xqc_var_buf_create(4096);
    xqc_int_t ret = XQC_OK;


    ret = xqc_stable_get_nv(10, nbuf, vbuf);
    xqc_stable_entry_t *entry = &xqc_g_static_table[10];
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, entry->nv.name.data) == 0
              && strcmp(vbuf->data, entry->nv.value.data) == 0);

    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_stable_get_nv(10, NULL, vbuf);
    CU_ASSERT(ret != XQC_OK);

    /* only get name */
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_stable_get_nv(10, nbuf, NULL);
    CU_ASSERT(ret == XQC_OK);

    /* overflow */
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_stable_get_nv(10000, nbuf, vbuf);
    CU_ASSERT(ret != XQC_OK);

    xqc_var_buf_free(nbuf);
    xqc_var_buf_free(vbuf);
}


void
xqc_test_stable()
{
    xqc_test_static_table_lookup_basic();
    xqc_test_static_table_lookup_robust();
    xqc_test_static_table_lookup_nv_matched();
    xqc_test_static_table_lookup_name_matched();

    xqc_test_static_table_get_nv_basic();
    xqc_test_static_table_get_nv_robust();
}

