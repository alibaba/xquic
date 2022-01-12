#include "src/http3/xqc_h3_header.h"

xqc_int_t
xqc_h3_headers_create_buf(xqc_http_headers_t *headers, size_t capacity)
{
    headers->headers = xqc_malloc(sizeof(xqc_http_header_t) * capacity);
    if (headers->headers == NULL) {
        headers->count = 0;
        headers->capacity = 0;
        return -XQC_H3_EMALLOC;
    }

    headers->capacity = capacity;
    headers->count = 0;
    return XQC_OK;
}

xqc_int_t
xqc_h3_headers_realloc_buf(xqc_http_headers_t *headers, size_t capacity)
{
    if (headers->count > capacity) {
        return -XQC_H3_EPARAM;
    }

    xqc_http_header_t *old = headers->headers;

    headers->headers = xqc_malloc(sizeof(xqc_http_header_t) * capacity);
    if (headers->headers == NULL) {
        return -XQC_H3_EMALLOC;
    }

    headers->capacity = capacity;
    memcpy(headers->headers, old, headers->count * sizeof(xqc_http_header_t));
    xqc_free(old);

    return XQC_OK;
}


void
xqc_h3_headers_clear(xqc_http_headers_t *headers)
{
    xqc_http_header_t *header;

    if (headers == NULL || headers->headers == NULL) {
        return;
    }

    for (xqc_int_t i = 0; i < headers->count; i++) {
        header = &headers->headers[i];

        /* free name */
        if (header->name.iov_base) {
            xqc_free(header->name.iov_base);
            header->name.iov_base = NULL;
            header->name.iov_len = 0;
        }

        /* free value */
        if (header->value.iov_base) {
            xqc_free(header->value.iov_base);
            header->value.iov_base = NULL;
            header->value.iov_len = 0;
        }
    }

    headers->count = 0;
}


void
xqc_h3_headers_free(xqc_http_headers_t *headers)
{
    if (headers->headers == NULL) {
        return;
    }

    /* free name-value memory */
    xqc_h3_headers_clear(headers);

    /* free headers memory */
    xqc_free(headers->headers);
    headers->headers = NULL;
    headers->count = 0;
    headers->capacity = 0;
}


void
xqc_h3_headers_initial(xqc_http_headers_t *headers)
{
    headers->headers = NULL;
    headers->count = 0;
    headers->capacity = 0;
}


/**
 * from nghttp3
 * Copyright (c) 2018 nghttp3 contributors
 */
xqc_hdr_type_t
xqc_h3_hdr_type(unsigned char *name, size_t nlen)
{
    switch (nlen) {
    case 3:
        switch (name[2]) {
        case 'e':
            if (xqc_memeq("ag", name, 2)) {
                return XQC_HDR_AGE;
            }
            break;
        }
        break;
    case 4:
        switch (name[3]) {
        case 'e':
            if (xqc_memeq("dat", name, 3)) {
                return XQC_HDR_DATE;
            }
            break;
        case 'g':
            if (xqc_memeq("eta", name, 3)) {
                return XQC_HDR_ETAG;
            }
            break;
        case 'k':
            if (xqc_memeq("lin", name, 3)) {
                return XQC_HDR_LINK;
            }
            break;
        case 'y':
            if (xqc_memeq("var", name, 3)) {
                return XQC_HDR_VARY;
            }
            break;
        }
        break;
    case 5:
        switch (name[4]) {
        case 'e':
            if (xqc_memeq("rang", name, 4)) {
                return XQC_HDR_RANGE;
            }
            break;
        case 'h':
            if (xqc_memeq(":pat", name, 4)) {
                return XQC_HDR__PATH;
            }
            break;
        }
        break;
    case 6:
        switch (name[5]) {
        case 'e':
            if (xqc_memeq("cooki", name, 5)) {
                return XQC_HDR_COOKIE;
            }
            break;
        case 'n':
            if (xqc_memeq("origi", name, 5)) {
                return XQC_HDR_ORIGIN;
            }
            break;
        case 'r':
            if (xqc_memeq("serve", name, 5)) {
                return XQC_HDR_SERVER;
            }
            break;
        case 't':
            if (xqc_memeq("accep", name, 5)) {
                return XQC_HDR_ACCEPT;
            }
            break;
        }
        break;
    case 7:
        switch (name[6]) {
        case 'c':
            if (xqc_memeq("alt-sv", name, 6)) {
                return XQC_HDR_ALT_SVC;
            }
            break;
        case 'd':
            if (xqc_memeq(":metho", name, 6)) {
                return XQC_HDR__METHOD;
            }
            break;
        case 'e':
            if (xqc_memeq(":schem", name, 6)) {
                return XQC_HDR__SCHEME;
            }
            if (xqc_memeq("purpos", name, 6)) {
                return XQC_HDR_PURPOSE;
            }
            break;
        case 'r':
            if (xqc_memeq("refere", name, 6)) {
                return XQC_HDR_REFERER;
            }
            break;
        case 's':
            if (xqc_memeq(":statu", name, 6)) {
                return XQC_HDR__STATUS;
            }
            break;
        }
        break;
    case 8:
        switch (name[7]) {
        case 'e':
            if (xqc_memeq("if-rang", name, 7)) {
                return XQC_HDR_IF_RANGE;
            }
            break;
        case 'n':
            if (xqc_memeq("locatio", name, 7)) {
                return XQC_HDR_LOCATION;
            }
            break;
        }
        break;
    case 9:
        switch (name[8]) {
        case 'd':
            if (xqc_memeq("forwarde", name, 8)) {
                return XQC_HDR_FORWARDED;
            }
            break;
        case 't':
            if (xqc_memeq("expect-c", name, 8)) {
                return XQC_HDR_EXPECT_CT;
            }
            break;
        }
        break;
    case 10:
        switch (name[9]) {
        case 'a':
            if (xqc_memeq("early-dat", name, 9)) {
                return XQC_HDR_EARLY_DATA;
            }
            break;
        case 'e':
            if (xqc_memeq("set-cooki", name, 9)) {
                return XQC_HDR_SET_COOKIE;
            }
            break;
        case 't':
            if (xqc_memeq("user-agen", name, 9)) {
                return XQC_HDR_USER_AGENT;
            }
            break;
        case 'y':
            if (xqc_memeq(":authorit", name, 9)) {
                return XQC_HDR__AUTHORITY;
            }
            break;
        }
        break;
    case 12:
        switch (name[11]) {
        case 'e':
            if (xqc_memeq("content-typ", name, 11)) {
                return XQC_HDR_CONTENT_TYPE;
            }
            break;
        }
        break;
    case 13:
        switch (name[12]) {
        case 'd':
            if (xqc_memeq("last-modifie", name, 12)) {
                return XQC_HDR_LAST_MODIFIED;
            }
            break;
        case 'h':
            if (xqc_memeq("if-none-matc", name, 12)) {
                return XQC_HDR_IF_NONE_MATCH;
            }
            break;
        case 'l':
            if (xqc_memeq("cache-contro", name, 12)) {
                return XQC_HDR_CACHE_CONTROL;
            }
            break;
        case 'n':
            if (xqc_memeq("authorizatio", name, 12)) {
                return XQC_HDR_AUTHORIZATION;
            }
            break;
        case 's':
            if (xqc_memeq("accept-range", name, 12)) {
                return XQC_HDR_ACCEPT_RANGES;
            }
            break;
        }
        break;
    case 14:
        switch (name[13]) {
        case 'h':
            if (xqc_memeq("content-lengt", name, 13)) {
                return XQC_HDR_CONTENT_LENGTH;
            }
            break;
        }
        break;
    case 15:
        switch (name[14]) {
        case 'e':
            if (xqc_memeq("accept-languag", name, 14)) {
                return XQC_HDR_ACCEPT_LANGUAGE;
            }
            break;
        case 'g':
            if (xqc_memeq("accept-encodin", name, 14)) {
                return XQC_HDR_ACCEPT_ENCODING;
            }
            break;
        case 'r':
            if (xqc_memeq("x-forwarded-fo", name, 14)) {
                return XQC_HDR_X_FORWARDED_FOR;
            }
            break;
        case 's':
            if (xqc_memeq("x-frame-option", name, 14)) {
                return XQC_HDR_X_FRAME_OPTIONS;
            }
            break;
        }
        break;
    case 16:
        switch (name[15]) {
        case 'g':
            if (xqc_memeq("content-encodin", name, 15)) {
                return XQC_HDR_CONTENT_ENCODING;
            }
            break;
        case 'n':
            if (xqc_memeq("x-xss-protectio", name, 15)) {
                return XQC_HDR_X_XSS_PROTECTION;
            }
            break;
        }
        break;
    case 17:
        switch (name[16]) {
        case 'e':
            if (xqc_memeq("if-modified-sinc", name, 16)) {
                return XQC_HDR_IF_MODIFIED_SINCE;
            }
            break;
        }
        break;
    case 19:
        switch (name[18]) {
        case 'n':
            if (xqc_memeq("content-dispositio", name, 18)) {
                return XQC_HDR_CONTENT_DISPOSITION;
            }
            if (xqc_memeq("timing-allow-origi", name, 18)) {
                return XQC_HDR_TIMING_ALLOW_ORIGIN;
            }
            break;
        }
        break;
    case 22:
        switch (name[21]) {
        case 's':
            if (xqc_memeq("x-content-type-option", name, 21)) {
                return XQC_HDR_X_CONTENT_TYPE_OPTIONS;
            }
            break;
        }
        break;
    case 23:
        switch (name[22]) {
        case 'y':
            if (xqc_memeq("content-security-polic", name, 22)) {
                return XQC_HDR_CONTENT_SECURITY_POLICY;
            }
            break;
        }
        break;
    case 25:
        switch (name[24]) {
        case 's':
            if (xqc_memeq("upgrade-insecure-request", name, 24)) {
                return XQC_HDR_UPGRADE_INSECURE_REQUESTS;
            }
            break;
        case 'y':
            if (xqc_memeq("strict-transport-securit", name, 24)) {
                return XQC_HDR_STRICT_TRANSPORT_SECURITY;
            }
            break;
        }
        break;
    case 27:
        switch (name[26]) {
        case 'n':
            if (xqc_memeq("access-control-allow-origi", name, 26)) {
                return XQC_HDR_ACCESS_CONTROL_ALLOW_ORIGIN;
            }
            break;
        }
        break;
    case 28:
        switch (name[27]) {
        case 's':
            if (xqc_memeq("access-control-allow-header", name, 27)) {
                return XQC_HDR_ACCESS_CONTROL_ALLOW_HEADERS;
            }
            if (xqc_memeq("access-control-allow-method", name, 27)) {
                return XQC_HDR_ACCESS_CONTROL_ALLOW_METHODS;
            }
            break;
        }
        break;
    case 29:
        switch (name[28]) {
        case 'd':
            if (xqc_memeq("access-control-request-metho", name, 28)) {
                return XQC_HDR_ACCESS_CONTROL_REQUEST_METHOD;
            }
            break;
        case 's':
            if (xqc_memeq("access-control-expose-header", name, 28)) {
                return XQC_HDR_ACCESS_CONTROL_EXPOSE_HEADERS;
            }
            break;
        }
        break;
    case 30:
        switch (name[29]) {
        case 's':
            if (xqc_memeq("access-control-request-header", name, 29)) {
                return XQC_HDR_ACCESS_CONTROL_REQUEST_HEADERS;
            }
            break;
        }
        break;
    case 32:
        switch (name[31]) {
        case 's':
            if (xqc_memeq("access-control-allow-credential", name, 31)) {
                return XQC_HDR_ACCESS_CONTROL_ALLOW_CREDENTIALS;
            }
            break;
        }
        break;
    }

    return XQC_HDR_UNKNOWN;
}