/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_stable.h"
#include "src/common/xqc_hash.h"

#define XQC_STABLE_SIZE 99

#define XQC_HASH_SHIFT 11


typedef struct xqc_stable_entry_s {
    /* name-value pair */
    xqc_nv_t            nv;

    /* header type */
    xqc_hdr_type_t      type;

    /*
     * :status/access-control-allow-headers headers are not continuously distributed
     * in static table. when lookup these two headers, if name matched while value not,
     * this attribute is set to tell the next entry with the same name in static table 
     */
    uint64_t            hop;

} xqc_stable_entry_t;


/* the first index of a header in static table, with the same sequence of xqc_hdr_type_t */
static const uint64_t xqc_stable_header_idx[] = {
    [XQC_HDR__AUTHORITY] = 0,
    [XQC_HDR__PATH] = 1,
    [XQC_HDR_AGE] = 2,
    [XQC_HDR_CONTENT_DISPOSITION] = 3,
    [XQC_HDR_CONTENT_LENGTH] = 4,
    [XQC_HDR_COOKIE] = 5,
    [XQC_HDR_DATE] = 6,
    [XQC_HDR_ETAG] = 7,
    [XQC_HDR_IF_MODIFIED_SINCE] = 8,
    [XQC_HDR_IF_NONE_MATCH] = 9,
    [XQC_HDR_LAST_MODIFIED] = 10,
    [XQC_HDR_LINK] = 11,
    [XQC_HDR_LOCATION] = 12,
    [XQC_HDR_REFERER] = 13,
    [XQC_HDR_SET_COOKIE] = 14,
    [XQC_HDR__METHOD] = 15,
    [XQC_HDR__SCHEME] = 22,
    [XQC_HDR__STATUS] = 24,
    [XQC_HDR_ACCEPT] = 29,
    [XQC_HDR_ACCEPT_ENCODING] = 31,
    [XQC_HDR_ACCEPT_RANGES] = 32,
    [XQC_HDR_ACCESS_CONTROL_ALLOW_HEADERS] = 33,
    [XQC_HDR_ACCESS_CONTROL_ALLOW_ORIGIN] = 35,
    [XQC_HDR_CACHE_CONTROL] = 36,
    [XQC_HDR_CONTENT_ENCODING] = 42,
    [XQC_HDR_CONTENT_TYPE] = 44,
    [XQC_HDR_RANGE] = 55,
    [XQC_HDR_STRICT_TRANSPORT_SECURITY] = 56,
    [XQC_HDR_VARY] = 59,
    [XQC_HDR_X_CONTENT_TYPE_OPTIONS] = 61,
    [XQC_HDR_X_XSS_PROTECTION] = 62,
    /* :status repeated here with index 63 is repeated with index 24 */
    [XQC_HDR_ACCEPT_LANGUAGE] = 72,
    [XQC_HDR_ACCESS_CONTROL_ALLOW_CREDENTIALS] = 73,
    /* access-control-allow-headers with index 75 here is repeated with index 33 */
    [XQC_HDR_ACCESS_CONTROL_ALLOW_METHODS] = 76,
    [XQC_HDR_ACCESS_CONTROL_EXPOSE_HEADERS] = 79,
    [XQC_HDR_ACCESS_CONTROL_REQUEST_HEADERS] = 80,
    [XQC_HDR_ACCESS_CONTROL_REQUEST_METHOD] = 81,
    [XQC_HDR_ALT_SVC] = 83,
    [XQC_HDR_AUTHORIZATION] = 84,
    [XQC_HDR_CONTENT_SECURITY_POLICY] = 85,
    [XQC_HDR_EARLY_DATA] = 86,
    [XQC_HDR_EXPECT_CT] = 87,
    [XQC_HDR_FORWARDED] = 88,
    [XQC_HDR_IF_RANGE] = 89,
    [XQC_HDR_ORIGIN] = 90,
    [XQC_HDR_PURPOSE] = 91,
    [XQC_HDR_SERVER] = 92,
    [XQC_HDR_TIMING_ALLOW_ORIGIN] = 93,
    [XQC_HDR_UPGRADE_INSECURE_REQUESTS] = 94,
    [XQC_HDR_USER_AGENT] = 95,
    [XQC_HDR_X_FORWARDED_FOR] = 96,
    [XQC_HDR_X_FRAME_OPTIONS] = 97
};


xqc_stable_entry_t xqc_g_static_table[] = {
    /* 0 */
    {
        {{10, ":authority"}, {0, ""}},
        XQC_HDR__AUTHORITY
    },
    {
        {{5, ":path"}, {1, "/"}},
        XQC_HDR__PATH
    },
    {
        {{3, "age"}, {1, "0"}},
        XQC_HDR_AGE
    },
    {
        {{19, "content-disposition"}, {0, ""}},
        XQC_HDR_CONTENT_DISPOSITION
    },
    {
        {{14, "content-length"}, {1, "0"}},
        XQC_HDR_CONTENT_LENGTH
    },
    {
        {{6, "cookie"}, {0, ""}},
        XQC_HDR_COOKIE
    },
    {
        {{4, "date"}, {0, ""}},
        XQC_HDR_DATE
    },
    {
        {{4, "etag"}, {0, ""}},
        XQC_HDR_ETAG
    },
    /* 8 */
    {
        {{17, "if-modified-since"}, {0, ""}},
        XQC_HDR_IF_MODIFIED_SINCE
    },
    {
        {{13, "if-none-match"}, {0, ""}},
        XQC_HDR_IF_NONE_MATCH
    },
    {
        {{13, "last-modified"}, {0, ""}},
        XQC_HDR_LAST_MODIFIED
    },
    {
        {{4, "link"}, {0, ""}},
        XQC_HDR_LINK
    },
    {
        {{8, "location"}, {0, ""}},
        XQC_HDR_LOCATION
    },
    {
        {{7, "referer"}, {0, ""}},
        XQC_HDR_REFERER
    },
    {
        {{10, "set-cookie"}, {0, ""}},
        XQC_HDR_SET_COOKIE
    },
    {
        {{7, ":method"}, {7, "CONNECT"}},
        XQC_HDR__METHOD
    },
    /* 16 */
    {
        {{7, ":method"}, {6, "DELETE"}},
        XQC_HDR__METHOD
    },
    {
        {{7, ":method"}, {3, "GET"}},
        XQC_HDR__METHOD
    },
    {
        {{7, ":method"}, {4, "HEAD"}},
        XQC_HDR__METHOD
    },
    {
        {{7, ":method"}, {7, "OPTIONS"}},
        XQC_HDR__METHOD
    },
    {
        {{7, ":method"}, {4, "POST"}},
        XQC_HDR__METHOD
    },
    {
        {{7, ":method"}, {3, "PUT"}},
        XQC_HDR__METHOD
    },
    {
        {{7, ":scheme"}, {4, "http"}},
        XQC_HDR__SCHEME
    },
    {
        {{7, ":scheme"}, {5, "https"}},
        XQC_HDR__SCHEME
    },
    /* 24 */
    {
        {{7, ":status"}, {3, "103"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "200"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "304"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "404"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "503"}},
        XQC_HDR__STATUS,
        63      /* forward to index 63 to continue lookup if name matched while value not matched */
    },
    {
        {{6, "accept"}, {3, "*/*"}},
        XQC_HDR_ACCEPT
    },
    {
        {{6, "accept"}, {23, "application/dns-message"}},
        XQC_HDR_ACCEPT
    },
    {
        {{15, "accept-encoding"}, {17, "gzip, deflate, br"}},
        XQC_HDR_ACCEPT_ENCODING
    },
    /* 32 */
    {
        {{13, "accept-ranges"}, {5, "bytes"}},
        XQC_HDR_ACCEPT_RANGES
    },
    {
        {{28, "access-control-allow-headers"}, {13, "cache-control"}},
        XQC_HDR_ACCESS_CONTROL_ALLOW_HEADERS
    },
    {
        {{28, "access-control-allow-headers"}, {12, "content-type"}},
        XQC_HDR_ACCESS_CONTROL_ALLOW_HEADERS,
        75      /* forward to index 75 to continue lookup if name matched while value not matched */
    },
    {
        {{27, "access-control-allow-origin"}, {1, "*"}},
        XQC_HDR_ACCESS_CONTROL_ALLOW_ORIGIN
    },
    {
        {{13, "cache-control"}, {9, "max-age=0"}},
        XQC_HDR_CACHE_CONTROL
    },
    {
        {{13, "cache-control"}, {15, "max-age=2592000"}},
        XQC_HDR_CACHE_CONTROL
    },
    {
        {{13, "cache-control"}, {14, "max-age=604800"}},
        XQC_HDR_CACHE_CONTROL
    },
    {
        {{13, "cache-control"}, {8, "no-cache"}},
        XQC_HDR_CACHE_CONTROL
    },
    /* 40 */
    {
        {{13, "cache-control"}, {8, "no-store"}},
        XQC_HDR_CACHE_CONTROL
    },
    {
        {{13, "cache-control"}, {24, "public, max-age=31536000"}},
        XQC_HDR_CACHE_CONTROL
    },
    {
        {{16, "content-encoding"}, {2, "br"}},
        XQC_HDR_CONTENT_ENCODING
    },
    {
        {{16, "content-encoding"}, {4, "gzip"}},
        XQC_HDR_CONTENT_ENCODING
    },
    {
        {{12, "content-type"}, {23, "application/dns-message"}},
        XQC_HDR_CONTENT_TYPE
    },
    {
        {{12, "content-type"}, {22, "application/javascript"}},
        XQC_HDR_CONTENT_TYPE
    },
    {
        {{12, "content-type"}, {16, "application/json"}},
        XQC_HDR_CONTENT_TYPE
    },
    {
        {{12, "content-type"}, {33, "application/x-www-form-urlencoded"}},
        XQC_HDR_CONTENT_TYPE
    },
    /* 48 */
    {
        {{12, "content-type"}, {9, "image/gif"}},
        XQC_HDR_CONTENT_TYPE
    },
    {
        {{12, "content-type"}, {10, "image/jpeg"}},
        XQC_HDR_CONTENT_TYPE
    },
    {
        {{12, "content-type"}, {9, "image/png"}},
        XQC_HDR_CONTENT_TYPE
    },
    {
        {{12, "content-type"}, {8, "text/css"}},
        XQC_HDR_CONTENT_TYPE
    },
    {
        {{12, "content-type"}, {24, "text/html; charset=utf-8"}},
        XQC_HDR_CONTENT_TYPE
    },
    {
        {{12, "content-type"}, {10, "text/plain"}},
        XQC_HDR_CONTENT_TYPE
    },
    {
        {{12, "content-type"}, {24, "text/plain;charset=utf-8"}},
        XQC_HDR_CONTENT_TYPE
    },
    {
        {{5, "range"}, {8, "bytes=0-"}},
        XQC_HDR_RANGE
    },
    /* 56 */
    {
        {{25, "strict-transport-security"}, {16, "max-age=31536000"}},
        XQC_HDR_STRICT_TRANSPORT_SECURITY
    },
    {
        {{25, "strict-transport-security"}, {35, "max-age=31536000; includesubdomains"}},
        XQC_HDR_STRICT_TRANSPORT_SECURITY
    },
    {
        {{25, "strict-transport-security"}, {44, "max-age=31536000; includesubdomains; preload"}},
        XQC_HDR_STRICT_TRANSPORT_SECURITY
    },
    {
        {{4, "vary"}, {15, "accept-encoding"}},
        XQC_HDR_VARY
    },
    {
        {{4, "vary"}, {6, "origin"}},
        XQC_HDR_VARY
    },
    {
        {{22, "x-content-type-options"}, {7, "nosniff"}},
        XQC_HDR_X_CONTENT_TYPE_OPTIONS
    },
    {
        {{16, "x-xss-protection"}, {13, "1; mode=block"}},
        XQC_HDR_X_XSS_PROTECTION
    },
    {
        {{7, ":status"}, {3, "100"}},
        XQC_HDR__STATUS
    },
    /* 64 */
    {
        {{7, ":status"}, {3, "204"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "206"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "302"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "400"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "403"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "421"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "425"}},
        XQC_HDR__STATUS
    },
    {
        {{7, ":status"}, {3, "500"}},
        XQC_HDR__STATUS
    },
    /* 72 */
    {
        {{15, "accept-language"}, {0, ""}},
        XQC_HDR_ACCEPT_LANGUAGE
    },
    {
        {{32, "access-control-allow-credentials"}, {5, "FALSE"}},
        XQC_HDR_ACCESS_CONTROL_ALLOW_CREDENTIALS
    },
    {
        {{32, "access-control-allow-credentials"}, {4, "TRUE"}},
        XQC_HDR_ACCESS_CONTROL_ALLOW_CREDENTIALS
    },
    {
        {{28, "access-control-allow-headers"}, {1, "*"}},
        XQC_HDR_ACCESS_CONTROL_ALLOW_HEADERS
    },
    {
        {{28, "access-control-allow-methods"}, {3, "get"}},
        XQC_HDR_ACCESS_CONTROL_ALLOW_METHODS
    },
    {
        {{28, "access-control-allow-methods"}, {18, "get, post, options"}},
        XQC_HDR_ACCESS_CONTROL_ALLOW_METHODS
    },
    {
        {{28, "access-control-allow-methods"}, {7, "options"}},
        XQC_HDR_ACCESS_CONTROL_ALLOW_METHODS
    },
    {
        {{29, "access-control-expose-headers"}, {14, "content-length"}},
        XQC_HDR_ACCESS_CONTROL_EXPOSE_HEADERS
    },
    /* 80 */
    {
        {{30, "access-control-request-headers"}, {12, "content-type"}},
        XQC_HDR_ACCESS_CONTROL_REQUEST_HEADERS
    },
    {
        {{29, "access-control-request-method"}, {3, "get"}},
        XQC_HDR_ACCESS_CONTROL_REQUEST_METHOD
    },
    {
        {{29, "access-control-request-method"}, {4, "post"}},
        XQC_HDR_ACCESS_CONTROL_REQUEST_METHOD
    },
    {
        {{7, "alt-svc"}, {5, "clear"}},
        XQC_HDR_ALT_SVC
    },
    {
        {{13, "authorization"}, {0, ""}},
        XQC_HDR_AUTHORIZATION
    },
    {
        {{23, "content-security-policy"}, {53, "script-src 'none'; object-src 'none'; base-uri 'none'"}},
        XQC_HDR_CONTENT_SECURITY_POLICY
    },
    {
        {{10, "early-data"}, {1, "1"}},
        XQC_HDR_EARLY_DATA
    },
    {
        {{9, "expect-ct"}, {0, ""}},
        XQC_HDR_EXPECT_CT
    },
    /* 88 */
    {
        {{9, "forwarded"}, {0, ""}},
        XQC_HDR_FORWARDED
    },
    {
        {{8, "if-range"}, {0, ""}},
        XQC_HDR_IF_RANGE
    },
    {
        {{6, "origin"}, {0, ""}},
        XQC_HDR_ORIGIN
    },
    {
        {{7, "purpose"}, {8, "prefetch"}},
        XQC_HDR_PURPOSE
    },
    {
        {{6, "server"}, {0, ""}},
        XQC_HDR_SERVER
    },
    {
        {{19, "timing-allow-origin"}, {1, "*"}},
        XQC_HDR_TIMING_ALLOW_ORIGIN
    },
    {
        {{25, "upgrade-insecure-requests"}, {1, "1"}},
        XQC_HDR_UPGRADE_INSECURE_REQUESTS
    },
    {
        {{10, "user-agent"}, {0, ""}},
        XQC_HDR_USER_AGENT
    },
    /* 96 */
    {
        {{15, "x-forwarded-for"}, {0, ""}},
        XQC_HDR_X_FORWARDED_FOR
    },
    {
        {{15, "x-frame-options"}, {4, "deny"}},
        XQC_HDR_X_FRAME_OPTIONS
    },
    {
        {{15, "x-frame-options"}, {10, "sameorigin"}},
        XQC_HDR_X_FRAME_OPTIONS
    },
};


xqc_stable_entry_t *
xqc_stable_get_entry(uint64_t idx)
{
    if (idx >= XQC_STABLE_SIZE) {
        return NULL;
    }

    return &xqc_g_static_table[idx];
}


xqc_int_t
xqc_stable_get_nv(uint64_t idx, xqc_var_buf_t *name_buf, xqc_var_buf_t *value_buf)
{
    if (NULL == name_buf) {
        return -XQC_EPARAM;
    }

    xqc_stable_entry_t *entry = xqc_stable_get_entry(idx);
    if (entry == NULL) {
        return -XQC_EPARAM;
    }

    /* save name */
    xqc_int_t ret = xqc_var_buf_save_prepare(name_buf, entry->nv.name.len + 1);
    if (ret != XQC_OK) {
        return ret;
    }

    ret = xqc_var_buf_save_data(name_buf, entry->nv.name.data, entry->nv.name.len);
    if (ret != XQC_OK) {
        return ret;
    }
    name_buf->data[name_buf->data_len] = '\0';

    /* value_buf is allowed to be NULL if caller don't need value */
    if (value_buf == NULL) {
        return XQC_OK;
    }

    /* save value */
    ret = xqc_var_buf_save_prepare(value_buf, entry->nv.value.len + 1);
    if (ret != XQC_OK) {
        return ret;
    }

    ret = xqc_var_buf_save_data(value_buf, entry->nv.value.data, entry->nv.value.len);
    if (ret < 0) {
        return ret;
    }
    value_buf->data[value_buf->data_len] = '\0';

    return XQC_OK;
}


xqc_nv_ref_type_t
xqc_stable_lookup(unsigned char *name, size_t nlen, unsigned char *value, size_t vlen,
    xqc_hdr_type_t htype, uint64_t *idx)
{
    xqc_nv_ref_type_t ret = XQC_NV_REF_NONE;

    if (NULL == name || nlen == 0 || htype >= XQC_HDR_STATIC_TABLE_END) {
        return ret;
    }

    /* at least name is matched */
    uint64_t s_idx = xqc_stable_header_idx[htype];
    ret = XQC_NV_REF_NAME;
    *idx = s_idx;

    /* continue compare value, starts from s_idx */
    while (s_idx < XQC_STABLE_SIZE) {
        xqc_stable_entry_t *entry = &xqc_g_static_table[s_idx];
        if (entry->type != htype) {
            /* name type differs */
            break;
        }

        if (entry->nv.value.len == vlen
            && xqc_memeq(entry->nv.value.data, value, vlen))
        {
            /* both name and value are matched, break loop */
            ret = XQC_NV_REF_NAME_AND_VALUE;
            *idx = s_idx;
            break;
        }

        /* if hop is not 0, it means subsequent entry with same name exists, jump to hop */
        if (entry->hop != 0) {
            s_idx = entry->hop;

        } else {
            s_idx++;
        }
    }

    return ret;
}
