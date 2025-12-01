/**
 * xqc_webtransport_request.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_request.h"

void
wt_request_parse_request_parameter(xqc_wt_request_t *wt_request)
{
    char *parameters = wt_request->request_parameters;
}

xqc_wt_request_t *
xqc_wt_request_create(xqc_log_t *log)
{
    xqc_wt_request_t *wt_request = xqc_calloc(1, sizeof(xqc_wt_request_t));
    wt_request->request_headers  = xqc_calloc(1, sizeof(xqc_str_hash_table_t));
    uint8_t siphash_key[XQC_SIPHASH_KEY_SIZE] = {0};
    if (xqc_str_hash_init(wt_request->request_headers, xqc_default_allocator,
            16, 0, siphash_key, sizeof(siphash_key), log) != XQC_OK)
    {
        xqc_free(wt_request->request_headers);
        xqc_free(wt_request);
        return NULL;
    }
    return wt_request;
}

void
xqc_wt_request_destroy(xqc_wt_request_t *wt_request)
{
    if (wt_request->request_headers) {
        xqc_str_hash_release(wt_request->request_headers);
        xqc_free(wt_request->request_headers);
    }
    if (wt_request->request_stream_id) xqc_free(wt_request->request_stream_id);
    if (wt_request->request_parameters) xqc_free(wt_request->request_parameters);
    xqc_free(wt_request);
}

void
xqc_wt_request_table_insert(xqc_wt_request_t *wt_request, const char *key, const char *value)
{
    uint64_t               hash    = xqc_hash_string(key, strlen(key));
    xqc_str_hash_element_t element = {.str = {.data = (unsigned char *)key, .len = strlen(key)},
        .hash                              = hash,
        .value                             = (void *)value};
    xqc_str_hash_add(wt_request->request_headers, element);
}

char *
xqc_wt_request_table_find(xqc_wt_request_t *wt_request, const char *key)
{
    uint64_t  hash  = xqc_hash_string(key, strlen(key));
    // printf("key len = %d\n", strlen(key)) ;
    xqc_str_t str   = {.data = (unsigned char *)key, .len = strlen(key)};
    void     *value = xqc_str_hash_find(wt_request->request_headers, hash, str);
    if (value == NULL) {
        // xqc_log
        printf("error find key %s\n", key);
        return NULL;
    }
    return (char *)value;
}
