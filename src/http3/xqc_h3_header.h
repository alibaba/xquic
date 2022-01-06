/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQUIC_XQC_H3_HEADER_H
#define XQUIC_XQC_H3_HEADER_H

#include <xquic/xqc_http3.h>
#include "src/common/xqc_common_inc.h"
#include "src/http3/xqc_h3_defs.h"


/* header section and trailer section */
#define XQC_H3_REQUEST_MAX_HEADERS_CNT          2

typedef enum {
    XQC_H3_REQUEST_HEADER           = 0,
    XQC_H3_REQUEST_TRAILER          = 1,
} xqc_h3_header_type_t;


/**
 * @brief create headers array for xqc_http_headers_t
 * @param headers http headers
 * @param capacity total headers
 * @return XQC_OK for success
 */
xqc_int_t xqc_h3_headers_create_buf(xqc_http_headers_t *headers, size_t capacity);


/**
 * @brief resize headers array for xqc_http_headers_t
 * @param headers http headers
 * @param capacity new capacity
 * @return xqc_int_t 
 */
xqc_int_t xqc_h3_headers_realloc_buf(xqc_http_headers_t *headers, size_t capacity);


/**
 * @brief free name-value buffer for headers
 * @param headers http headers
 */
void xqc_h3_headers_clear(xqc_http_headers_t *headers);


/**
 * @brief free headers array and name-value buffer in them
 * @param headers http headers
 */
void xqc_h3_headers_free(xqc_http_headers_t *headers);


/**
 * @brief set http headers to be empty
 * @param headers http headers
 */
void xqc_h3_headers_initial(xqc_http_headers_t *headers);


/**
 * translated from nghttp3
 */
typedef enum {
    XQC_HDR__AUTHORITY = 0,
    XQC_HDR__PATH,
    XQC_HDR_AGE,
    XQC_HDR_CONTENT_DISPOSITION,
    XQC_HDR_CONTENT_LENGTH,
    XQC_HDR_COOKIE,
    XQC_HDR_DATE,
    XQC_HDR_ETAG,
    XQC_HDR_IF_MODIFIED_SINCE,
    XQC_HDR_IF_NONE_MATCH,
    XQC_HDR_LAST_MODIFIED,
    XQC_HDR_LINK,
    XQC_HDR_LOCATION,
    XQC_HDR_REFERER,
    XQC_HDR_SET_COOKIE,
    XQC_HDR__METHOD,
    XQC_HDR__SCHEME,
    XQC_HDR__STATUS,
    XQC_HDR_ACCEPT,
    XQC_HDR_ACCEPT_ENCODING,
    XQC_HDR_ACCEPT_RANGES,
    XQC_HDR_ACCESS_CONTROL_ALLOW_HEADERS,
    XQC_HDR_ACCESS_CONTROL_ALLOW_ORIGIN,
    XQC_HDR_CACHE_CONTROL,
    XQC_HDR_CONTENT_ENCODING,
    XQC_HDR_CONTENT_TYPE,
    XQC_HDR_RANGE,
    XQC_HDR_STRICT_TRANSPORT_SECURITY,
    XQC_HDR_VARY,
    XQC_HDR_X_CONTENT_TYPE_OPTIONS,
    XQC_HDR_X_XSS_PROTECTION ,
    XQC_HDR_ACCEPT_LANGUAGE,
    XQC_HDR_ACCESS_CONTROL_ALLOW_CREDENTIALS,
    XQC_HDR_ACCESS_CONTROL_ALLOW_METHODS,
    XQC_HDR_ACCESS_CONTROL_EXPOSE_HEADERS,
    XQC_HDR_ACCESS_CONTROL_REQUEST_HEADERS,
    XQC_HDR_ACCESS_CONTROL_REQUEST_METHOD,
    XQC_HDR_ALT_SVC,
    XQC_HDR_AUTHORIZATION,
    XQC_HDR_CONTENT_SECURITY_POLICY,
    XQC_HDR_EARLY_DATA,
    XQC_HDR_EXPECT_CT,
    XQC_HDR_FORWARDED,
    XQC_HDR_IF_RANGE,
    XQC_HDR_ORIGIN,
    XQC_HDR_PURPOSE,
    XQC_HDR_SERVER,
    XQC_HDR_TIMING_ALLOW_ORIGIN,
    XQC_HDR_UPGRADE_INSECURE_REQUESTS,
    XQC_HDR_USER_AGENT,
    XQC_HDR_X_FORWARDED_FOR,
    XQC_HDR_X_FRAME_OPTIONS,

    /* END of STATIC TABLE HEADERS */
    XQC_HDR_STATIC_TABLE_END,

    /* XQC_HDR_UNKNOWN shall be the largest enumerated values */
    XQC_HDR_UNKNOWN,
    /* NO VALUE SHALL BE ADD HERE */
} xqc_hdr_type_t;


/**
 * @brief parse header type
 * @param name header name
 * @param nlen header name len
 * @return XQC_HDR_UNKNOWN for not registered, others for valid header type
 */
xqc_hdr_type_t xqc_h3_hdr_type(unsigned char *name, size_t nlen);


#endif /* XQUIC_XQC_H3_HEADER_H */
