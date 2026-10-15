/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/frame/xqc_h3_frame.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/common/xqc_str.h"

#define XQC_H3_DECODE_DISCRETE_VINT_VALUE(pos, sz, pctx, fin) \
    do {                                                      \
        ssize_t nread = xqc_discrete_vint_parse((pos), (sz), (&pctx), (fin)); \
        if (nread < 0) {                                      \
            return -XQC_H3_DECODE_ERROR;                      \
        }                                                     \
        pos += nread;                                         \
        sz -= nread;                                          \
    } while(0)

#define XQC_H3_DECODE_FRM(function, pos, sz, frm, fin) \
    do {                                               \
        ssize_t nread = function((pos), (sz), (&frm), (fin)); \
        if (nread < 0) {                               \
            return -XQC_H3_DECODE_ERROR;               \
        }                                              \
        pos += nread;                                  \
        sz -= nread;                                   \
    } while(0)

static ssize_t xqc_h3_frm_parse_single_vint_payload(
    const unsigned char *p, size_t sz, xqc_discrete_int_pctx_t *vint,
    xqc_h3_frame_t *frame, xqc_bool_t *fin);


static ssize_t
xqc_h3_frm_parse_single_vint_payload(const unsigned char *p, size_t sz,
    xqc_discrete_int_pctx_t *vint, xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    ssize_t nread = xqc_discrete_vint_parse(p, sz, vint, fin);
    if (nread < 0) {
        return -XQC_H3_DECODE_ERROR;
    }

    /*
     * RFC 9114 Section 7.1 requires the payload to contain exactly its
     * identified fields. Track encoded bytes because RFC 9000 Section 16
     * permits a varint to use more than its minimum encoding length.
     */
    frame->consumed_len += nread;
    if (frame->consumed_len > frame->len
        || (*fin && frame->consumed_len != frame->len))
    {
        return -XQC_H3_DECODE_ERROR;
    }

    return nread;
}


void
xqc_h3_frm_reset_pctx(xqc_h3_frame_pctx_t *pctx)
{
    switch (pctx->frame.type) {
    case XQC_H3_FRM_DATA:
        break;
    case XQC_H3_FRM_HEADERS:
        break;
    case XQC_H3_FRM_CANCEL_PUSH:
        break;
    case XQC_H3_FRM_SETTINGS:
        xqc_var_buf_free(pctx->frame.frame_payload.settings.setting);
        break;
    case XQC_H3_FRM_PUSH_PROMISE:
        xqc_var_buf_free(pctx->frame.frame_payload.push_promise.encoded_field_section);
        break;
    case XQC_H3_FRM_GOAWAY:
        break;
    case XQC_H3_FRM_MAX_PUSH_ID:
        break;
    case XQC_H3_FRM_RESERVED_PRIORITY:
    case XQC_H3_FRM_RESERVED_PING:
    case XQC_H3_FRM_RESERVED_WINDOW_UPDATE:
    case XQC_H3_FRM_RESERVED_CONTINUATION:
        break;
    case XQC_H3_EXT_FRM_BIDI_STREAM_TYPE:
        break;
    case XQC_H3_FRM_UNKNOWN:
        break;
    }
    memset(pctx, 0, sizeof(xqc_h3_frame_pctx_t));
    pctx->state = XQC_H3_FRM_STATE_TYPE;
    pctx->frame.type = XQC_H3_FRM_UNKNOWN;
}


ssize_t
xqc_h3_frm_parse_cancel_push(const unsigned char *p, size_t sz, xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    xqc_h3_frame_cancel_push_t *cancel_push = &frame->frame_payload.cancel_push;
    return xqc_h3_frm_parse_single_vint_payload(p, sz,
        &cancel_push->push_id, frame, fin);
}

ssize_t
xqc_h3_frm_parse_settings(const unsigned char *p, size_t sz, xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    const unsigned char *pos = p;
    *fin = XQC_FALSE;
    xqc_h3_frame_settings_t *settings = &frame->frame_payload.settings;
    if (settings->setting == NULL) {
        /* RFC 9114 Section 7.2.4: reject oversized SETTINGS to prevent memory exhaustion */
        if (frame->len > XQC_H3_SETTINGS_MAX_FRAME_SIZE) {
            return -XQC_H3_DECODE_ERROR;
        }
        if (frame->len > XQC_VAR_BUF_INIT_SIZE) {
            settings->setting = xqc_var_buf_create_with_limit(XQC_VAR_BUF_INIT_SIZE, XQC_H3_SETTINGS_MAX_FRAME_SIZE);
        } else {
            settings->setting = xqc_var_buf_create_with_limit(frame->len, XQC_H3_SETTINGS_MAX_FRAME_SIZE);
        }
        if (settings->setting == NULL) {
            return -XQC_H3_EMALLOC;
        }
    }

    ssize_t len = xqc_min(sz, frame->len - settings->setting->data_len);
    xqc_int_t ret = xqc_var_buf_save_data(settings->setting, pos, len);
    if (ret != XQC_OK) {
        return -XQC_H3_DECODE_ERROR;
    }
    pos += len;
    *fin = settings->setting->data_len == frame->len ? XQC_TRUE : XQC_FALSE;

    return pos - p;
}

ssize_t
xqc_h3_frm_parse_push_promise(const unsigned char *p, size_t sz, xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    const unsigned char *pos = p;
    *fin = XQC_FALSE;
    xqc_bool_t fin_t;
    xqc_h3_frame_push_promise_t *push_promise = &frame->frame_payload.push_promise;
    if (push_promise->count == 0 && sz > 0) {
        XQC_H3_DECODE_DISCRETE_VINT_VALUE(pos, sz, push_promise->push_id, &fin_t);
        if (fin_t) {
            push_promise->count = 1;
        }
    }
    if (push_promise->count == 1 && sz > 0) {
        if (frame->len < xqc_vint_len_by_val(push_promise->push_id.vi)) {
            return -XQC_EVINTREAD;
        }
        ssize_t payload_len = frame->len - xqc_vint_len_by_val(push_promise->push_id.vi);
        if (push_promise->encoded_field_section == NULL) {
            /* reject oversized PUSH_PROMISE to prevent memory exhaustion */
            if (payload_len > XQC_H3_PUSH_PROMISE_MAX_PAYLOAD_SIZE) {
                return -XQC_H3_DECODE_ERROR;
            }
            if (payload_len > XQC_VAR_BUF_INIT_SIZE) {
                push_promise->encoded_field_section = xqc_var_buf_create_with_limit(XQC_VAR_BUF_INIT_SIZE, XQC_H3_PUSH_PROMISE_MAX_PAYLOAD_SIZE);
            } else {
                push_promise->encoded_field_section = xqc_var_buf_create_with_limit(payload_len, XQC_H3_PUSH_PROMISE_MAX_PAYLOAD_SIZE);
            }
            if (push_promise->encoded_field_section == NULL) {
                return -XQC_H3_EMALLOC;
            }
        }
        ssize_t len = xqc_min(sz, payload_len - push_promise->encoded_field_section->data_len);
        xqc_int_t ret = xqc_var_buf_save_data(push_promise->encoded_field_section, pos, len);
        if (ret != XQC_OK) {
            return -XQC_H3_DECODE_ERROR;
        }
        pos += len;
        *fin = xqc_vint_len_by_val(push_promise->push_id.vi) + push_promise->encoded_field_section->data_len == frame->len ? XQC_TRUE : XQC_FALSE;
    }
    return pos -p;
}

ssize_t
xqc_h3_frm_parse_goaway(const unsigned char *p, size_t sz, xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    xqc_h3_frame_goaway_t *goaway = &frame->frame_payload.goaway;
    return xqc_h3_frm_parse_single_vint_payload(p, sz,
        &goaway->stream_id, frame, fin);
}

ssize_t
xqc_h3_frm_parse_max_push_id(const unsigned char *p, size_t sz, xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    xqc_h3_frame_max_push_id_t *max_push_id = &frame->frame_payload.max_push_id;
    return xqc_h3_frm_parse_single_vint_payload(p, sz,
        &max_push_id->push_id, frame, fin);
}

ssize_t
xqc_h3_ext_frm_parse_bidi_stream_type(const unsigned char *p, size_t sz, xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    const unsigned char *pos = p;
    *fin = XQC_FALSE;
    xqc_h3_ext_frame_bidi_stream_type_t *stream_type = &frame->frame_payload.stream_type;
    XQC_H3_DECODE_DISCRETE_VINT_VALUE(pos, sz, stream_type->stream_type, fin);
    return pos - p;
}

xqc_bool_t
xqc_h3_frm_is_h2_reserved(uint64_t frame_type)
{
    switch (frame_type) {
    case XQC_H3_FRM_RESERVED_PRIORITY:
    case XQC_H3_FRM_RESERVED_PING:
    case XQC_H3_FRM_RESERVED_WINDOW_UPDATE:
    case XQC_H3_FRM_RESERVED_CONTINUATION:
        return XQC_TRUE;
    default:
        return XQC_FALSE;
    }
}


ssize_t
xqc_h3_frm_parse_reserved(const unsigned char *p, size_t sz,
    xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    const unsigned char    *pos  = p;
    size_t                  read = 0;

    *fin = XQC_FALSE;

    /* skip until all payload read or all bytes consumed */
    read = xqc_min(frame->len - frame->consumed_len, sz);
    pos += read;
    frame->consumed_len += read;

    /* all bytes consumed */
    if (frame->len == frame->consumed_len) {
        *fin = XQC_TRUE;
    }

    return pos - p;
}

ssize_t
xqc_h3_frm_parse(const unsigned char *p, size_t sz, xqc_h3_frame_pctx_t *pctx)
{
    const unsigned char *pos = p;
    xqc_bool_t fin = 0;

    if (pctx->state == XQC_H3_FRM_STATE_END) {
        return -XQC_H3_DECODE_ERROR;
    }

    if (pctx->state == XQC_H3_FRM_STATE_TYPE) {
        XQC_H3_DECODE_DISCRETE_VINT_VALUE(pos, sz, pctx->pctx, &fin);
        if (fin) {
            pctx->frame.type = pctx->pctx.vi;
            xqc_discrete_int_pctx_clear(&pctx->pctx);
            pctx->state = XQC_H3_FRM_STATE_LEN;
            if (xqc_h3_frm_is_h2_reserved(pctx->frame.type)) {
                return -XQC_H3_RESERVED_FRAME_UNEXPECTED;
            }
            fin = 0;
        }
    }

    if (sz == 0) {
        return pos - p;
    }

    if (pctx->state == XQC_H3_FRM_STATE_LEN) {
        XQC_H3_DECODE_DISCRETE_VINT_VALUE(pos, sz, pctx->pctx, &fin);
        if (fin) {
            pctx->frame.len = pctx->pctx.vi;
            pctx->frame.consumed_len = 0;
            xqc_discrete_int_pctx_clear(&pctx->pctx);
            memset(&pctx->frame.frame_payload, 0, sizeof(xqc_h3_frame_pl_t));
            pctx->state = XQC_H3_FRM_STATE_PAYLOAD;
            if (pctx->frame.len == 0) {
                /* RFC 9114 Section 7.1: required fields cannot be absent. */
                switch (pctx->frame.type) {
                case XQC_H3_FRM_CANCEL_PUSH:
                case XQC_H3_FRM_PUSH_PROMISE:
                case XQC_H3_FRM_GOAWAY:
                case XQC_H3_FRM_MAX_PUSH_ID:
                case XQC_H3_EXT_FRM_BIDI_STREAM_TYPE:
                    return -XQC_H3_DECODE_ERROR;
                default:
                    pctx->state = XQC_H3_FRM_STATE_END;
                    break;
                }
            }
            fin = 0;
        }
    }

    if (sz == 0) {
        return pos - p;
    }

    if (pctx->state == XQC_H3_FRM_STATE_PAYLOAD) {
        switch (pctx->frame.type) {
        case XQC_H3_FRM_DATA: {
            break;
        }
        case XQC_H3_FRM_HEADERS: {
            break;
        }
        case XQC_H3_FRM_CANCEL_PUSH: {
            XQC_H3_DECODE_FRM(xqc_h3_frm_parse_cancel_push, pos, sz, pctx->frame, &fin);
            break;
        }
        case XQC_H3_FRM_SETTINGS: {
            XQC_H3_DECODE_FRM(xqc_h3_frm_parse_settings, pos, sz, pctx->frame, &fin);
            break;
        }
        case XQC_H3_FRM_PUSH_PROMISE: {
            XQC_H3_DECODE_FRM(xqc_h3_frm_parse_push_promise, pos, sz, pctx->frame, &fin);
            break;
        }
        case XQC_H3_FRM_GOAWAY: {
            XQC_H3_DECODE_FRM(xqc_h3_frm_parse_goaway, pos, sz, pctx->frame, &fin);
            break;
        }
        case XQC_H3_FRM_MAX_PUSH_ID: {
            XQC_H3_DECODE_FRM(xqc_h3_frm_parse_max_push_id, pos, sz, pctx->frame, &fin);
            break;
        }
        case XQC_H3_EXT_FRM_BIDI_STREAM_TYPE: {
            XQC_H3_DECODE_FRM(xqc_h3_ext_frm_parse_bidi_stream_type, pos, sz, pctx->frame, &fin);
            break;
        }
        default: {
            XQC_H3_DECODE_FRM(xqc_h3_frm_parse_reserved, pos, sz, pctx->frame, &fin);
            break;
        }
        }

        if (fin) {
            pctx->state = XQC_H3_FRM_STATE_END;
        }
    }

    return pos - p;
}

ssize_t
xqc_h3_frm_parse_setting(xqc_var_buf_t *data, void *user_data)
{
    xqc_h3_conn_t             *h3c = (xqc_h3_conn_t *)user_data;
    xqc_h3_setting_t          *entries = NULL;
    size_t                     data_len = data == NULL ? 0 : data->data_len;
    size_t                     capacity = (data_len + 1) / 2;
    size_t                     count = 0;
    size_t                     extern_count = 0;
    size_t                     offset = 0;
    xqc_bool_t                 fin;
    xqc_discrete_int_pctx_t    identifier;
    xqc_discrete_int_pctx_t    value;
    ssize_t                    read;
    xqc_int_t                  ret;
#ifndef XQC_ONLY_CLIENT_LIB
    size_t                     fingerprint_len = 0;
    xqc_bool_t                 fingerprint_error = XQC_FALSE;
    size_t                     entry_len;
    size_t                     separator_len;
    unsigned char             *pos;
    unsigned char             *last;
#endif

    if (capacity > 0) {
        entries = xqc_malloc(capacity * sizeof(*entries));
        if (entries == NULL) {
            XQC_H3_CONN_ERR(h3c, H3_INTERNAL_ERROR, -XQC_H3_EMALLOC);
            ret = -H3_INTERNAL_ERROR;
            goto finish;
        }
    }

    while (offset < data_len) {
        memset(&identifier, 0, sizeof(xqc_discrete_int_pctx_t));
        memset(&value, 0, sizeof(xqc_discrete_int_pctx_t));

        fin = XQC_FALSE;
        read = xqc_discrete_vint_parse(data->data + offset,
                                       data_len - offset,
                                       &identifier, &fin);
        if (read < 0 || !fin) {
            goto frame_error;
        }
        offset += read;

        fin = XQC_FALSE;
        read = xqc_discrete_vint_parse(data->data + offset,
                                       data_len - offset, &value, &fin);
        if (read < 0 || !fin) {
            goto frame_error;
        }
        offset += read;

        if (identifier.vi >= XQC_H3_SETTINGS_H2_ENABLE_PUSH
            && identifier.vi <= XQC_H3_SETTINGS_H2_MAX_FRAME_SIZE)
        {
            xqc_log(h3c->log, XQC_LOG_ERROR,
                    "|reserved HTTP/2 setting|identifier:%ui|", identifier.vi);
            goto settings_error;
        }

        for (size_t i = 0; i < count; i++) {
            if (entries[i].identifier == identifier.vi) {
                xqc_log(h3c->log, XQC_LOG_ERROR,
                        "|duplicate setting|identifier:%ui|", identifier.vi);
                goto settings_error;
            }
        }

        entries[count].identifier = identifier.vi;
        entries[count].value = value.vi;
        count++;
    }

    for (size_t i = 0; i < count; i++) {
        ret = xqc_h3_conn_on_settings_entry_received(entries[i].identifier,
                                                      entries[i].value, h3c);
        if (ret != XQC_OK) {
            XQC_H3_CONN_ERR(h3c, H3_INTERNAL_ERROR,
                            -XQC_H3_EPROC_CONTROL);
            ret = -H3_INTERNAL_ERROR;
            goto finish;
        }
    }

#ifndef XQC_ONLY_CLIENT_LIB
    h3c->h3_settings_params[0] = '\0';
    for (size_t i = 0; i < count && !fingerprint_error; i++) {
        uint64_t setting_id = entries[i].identifier;
        if (setting_id != XQC_H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY
            && setting_id != XQC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE
            && setting_id != XQC_H3_SETTINGS_QPACK_BLOCKED_STREAMS)
        {
            continue;
        }

        separator_len = fingerprint_len == 0 ? 0 : 1;
        entry_len = xqc_uint64_decimal_len(setting_id) + 1
                    + xqc_uint64_decimal_len(entries[i].value);
        if (fingerprint_len + separator_len + entry_len
            > XQC_H3_FINGERPRINT_SETTINGS_MAX_LEN)
        {
            fingerprint_error = XQC_TRUE;
            xqc_memcpy(h3c->h3_settings_params,
                       XQC_H3_FINGERPRINT_ERROR_MARKER,
                       sizeof(XQC_H3_FINGERPRINT_ERROR_MARKER));
            continue;
        }

        pos = (unsigned char *)h3c->h3_settings_params + fingerprint_len;
        last = (unsigned char *)h3c->h3_settings_params
               + XQC_H3_FINGERPRINT_SETTINGS_MAX_LEN;
        if (separator_len) {
            *pos++ = ';';
        }
        pos = xqc_fmt_uint(pos, last, setting_id);
        *pos++ = ':';
        pos = xqc_fmt_uint(pos, last, entries[i].value);
        fingerprint_len = pos - (unsigned char *)h3c->h3_settings_params;
        h3c->h3_settings_params[fingerprint_len] = '\0';
    }
#endif

    for (size_t i = 0; i < count; i++) {
        uint64_t setting_id = entries[i].identifier;
        xqc_bool_t is_core =
            setting_id == XQC_H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY
            || setting_id == XQC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE
            || setting_id == XQC_H3_SETTINGS_QPACK_BLOCKED_STREAMS;
        /* RFC 9114 Section 7.2.4.1: reserved settings have no semantics. */
        xqc_bool_t is_grease = setting_id >= XQC_H3_SETTINGS_GREASE_FIRST
            && (setting_id - XQC_H3_SETTINGS_GREASE_FIRST)
                % XQC_H3_SETTINGS_GREASE_INTERVAL == 0;
        if (!is_core && !is_grease) {
            entries[extern_count++] = entries[i];
        }
    }

    /* Notify only after every core setting has been applied successfully. */
    if (h3c->h3_conn_callbacks.h3_conn_peer_extern_settings_notify) {
        xqc_h3_settings_result_t result =
            h3c->h3_conn_callbacks.h3_conn_peer_extern_settings_notify(
                h3c, entries, extern_count, h3c->user_data);
        if (result == XQC_H3_SETTINGS_REJECT) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|application rejected SETTINGS|");
            goto settings_error;
        }
        if (result != XQC_H3_SETTINGS_ACCEPT) {
            XQC_H3_CONN_ERR(h3c, H3_INTERNAL_ERROR,
                            -XQC_H3_EPROC_CONTROL);
            ret = -H3_INTERNAL_ERROR;
            goto finish;
        }
    }

    if (data != NULL) {
        data->consumed_len = data_len;
    }
    ret = XQC_OK;
    goto finish;

frame_error:
    xqc_log(h3c->log, XQC_LOG_ERROR,
            "|truncated setting|offset:%uz|length:%uz|", offset, data_len);
    XQC_H3_CONN_ERR(h3c, H3_FRAME_ERROR, -XQC_H3_DECODE_ERROR);
    ret = -H3_FRAME_ERROR;
    goto finish;

settings_error:
    XQC_H3_CONN_ERR(h3c, H3_SETTINGS_ERROR, -XQC_H3_SETTING_ERROR);
    ret = -H3_SETTINGS_ERROR;

finish:
    if (entries != NULL) {
        xqc_free(entries);
    }
    return ret;
}

xqc_int_t
xqc_h3_frm_write_headers(xqc_list_head_t *send_buf, xqc_var_buf_t *encoded_field_section,
    uint8_t fin)
{
    xqc_var_buf_t *buf = xqc_var_buf_create(xqc_put_varint_len(XQC_H3_FRM_HEADERS)
                                            + xqc_put_varint_len(encoded_field_section->data_len));
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, XQC_H3_FRM_HEADERS);
    pos = xqc_put_varint(pos, encoded_field_section->data_len);
    buf->data_len = pos - buf->data;

    xqc_int_t ret = xqc_list_buf_to_tail(send_buf, buf);
    if (ret != XQC_OK) {
        xqc_var_buf_free(buf);
        return ret;
    }

    encoded_field_section->fin_flag = fin;
    ret = xqc_list_buf_to_tail(send_buf, encoded_field_section);
    if (ret != XQC_OK) {
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_frm_write_data(xqc_list_head_t *send_buf, unsigned char *data, size_t size, uint8_t fin)
{
    xqc_var_buf_t *buf = xqc_var_buf_create(xqc_put_varint_len(XQC_H3_FRM_DATA)
                                            + xqc_put_varint_len(size) + size);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, XQC_H3_FRM_DATA);
    pos = xqc_put_varint(pos, size);
    buf->data_len = pos - buf->data;
    xqc_int_t ret = xqc_var_buf_save_data(buf, data, size);
    if (ret != XQC_OK) {
        xqc_var_buf_free(buf);
        return ret;
    }
    buf->fin_flag = fin;

    ret = xqc_list_buf_to_tail(send_buf, buf);
    if (ret != XQC_OK) {
        xqc_var_buf_free(buf);
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_frm_write_cancel_push(xqc_list_head_t *send_buf, uint64_t push_id, uint8_t fin)
{
    size_t len = xqc_put_varint_len(push_id);
    xqc_var_buf_t *buf = xqc_var_buf_create(xqc_put_varint_len(XQC_H3_FRM_CANCEL_PUSH)
                                            + xqc_put_varint_len(xqc_put_varint_len(push_id))
                                            + len);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, XQC_H3_FRM_CANCEL_PUSH);
    pos = xqc_put_varint(pos, len);
    pos = xqc_put_varint(pos, push_id);
    buf->data_len = pos - buf->data;
    buf->fin_flag = fin;

    xqc_int_t ret = xqc_list_buf_to_tail(send_buf, buf);
    if (ret != XQC_OK) {
        xqc_var_buf_free(buf);
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_frm_write_settings(xqc_list_head_t *send_buf,
    const xqc_h3_conn_settings_t *setting, uint8_t fin)
{
    if (xqc_h3_conn_settings_validate(setting, NULL) != XQC_OK) {
        return -XQC_EPARAM;
    }

    const xqc_h3_setting_t core_settings[] = {
        { XQC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
          setting->max_field_section_size },
        { XQC_H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
          setting->qpack_dec_max_table_capacity },
        { XQC_H3_SETTINGS_QPACK_BLOCKED_STREAMS,
          setting->qpack_blocked_streams },
    };
    size_t core_count = sizeof(core_settings) / sizeof(core_settings[0]);
    size_t count = core_count + setting->extern_settings_count;
    size_t len = 0;
    for (size_t i = 0; i < count; i++) {
        const xqc_h3_setting_t *entry = i < core_count
            ? &core_settings[i] : &setting->extern_settings[i - core_count];
        len += xqc_put_varint_len(entry->identifier);
        len += xqc_put_varint_len(entry->value);
    }

    xqc_var_buf_t *buf = xqc_var_buf_create(xqc_put_varint_len(XQC_H3_FRM_SETTINGS)
                                            + xqc_put_varint_len(len)
                                            + len);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, XQC_H3_FRM_SETTINGS);
    pos = xqc_put_varint(pos, len);
    for (size_t i = 0; i < count; i++) {
        const xqc_h3_setting_t *entry = i < core_count
            ? &core_settings[i] : &setting->extern_settings[i - core_count];
        pos = xqc_put_varint(pos, entry->identifier);
        pos = xqc_put_varint(pos, entry->value);
    }
    buf->data_len = pos - buf->data;
    buf->fin_flag = fin;

    xqc_int_t ret = xqc_list_buf_to_tail(send_buf, buf);
    if (ret != XQC_OK) {
        xqc_var_buf_free(buf);
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_frm_write_push_promise(xqc_list_head_t *send_buf, uint64_t push_id, xqc_var_buf_t *encoded_field_section,
    uint8_t fin)
{
    size_t push_id_len = xqc_put_varint_len(push_id);
    xqc_var_buf_t *buf = xqc_var_buf_create(xqc_put_varint_len(XQC_H3_FRM_PUSH_PROMISE)
                                            + xqc_put_varint_len(push_id_len + encoded_field_section->data_len)
                                            + push_id_len
                                            + encoded_field_section->data_len);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, XQC_H3_FRM_PUSH_PROMISE);
    pos = xqc_put_varint(pos, push_id_len + encoded_field_section->data_len);
    pos = xqc_put_varint(pos, push_id);
    buf->data_len = pos - buf->data;

    xqc_int_t ret = xqc_list_buf_to_tail(send_buf, buf);
    if (ret != XQC_OK) {
        xqc_var_buf_free(buf);
        return ret;
    }

    encoded_field_section->fin_flag = fin;
    ret = xqc_list_buf_to_tail(send_buf, encoded_field_section);
    if (ret != XQC_OK) {
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_frm_write_goaway(xqc_list_head_t *send_buf, uint64_t push_id, uint8_t fin)
{
    size_t len = xqc_put_varint_len(push_id);
    xqc_var_buf_t *buf = xqc_var_buf_create(xqc_put_varint_len(XQC_H3_FRM_GOAWAY)
                                            + xqc_put_varint_len(len)
                                            + len);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, XQC_H3_FRM_GOAWAY);
    pos = xqc_put_varint(pos, len);
    pos = xqc_put_varint(pos, push_id);
    buf->data_len = pos - buf->data;
    buf->fin_flag = fin;

    xqc_int_t ret = xqc_list_buf_to_tail(send_buf, buf);
    if (ret != XQC_OK) {
        xqc_var_buf_free(buf);
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_frm_write_max_push_id(xqc_list_head_t *send_buf, uint64_t push_id, uint8_t fin)
{
    size_t len = xqc_put_varint_len(push_id);
    xqc_var_buf_t *buf = xqc_var_buf_create(xqc_put_varint_len(XQC_H3_FRM_MAX_PUSH_ID)
                                            + xqc_put_varint_len(len)
                                            + len);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, XQC_H3_FRM_MAX_PUSH_ID);
    pos = xqc_put_varint(pos, len);
    pos = xqc_put_varint(pos, push_id);
    buf->data_len = pos - buf->data;
    buf->fin_flag = fin;

    xqc_int_t ret = xqc_list_buf_to_tail(send_buf, buf);
    if (ret != XQC_OK) {
        xqc_var_buf_free(buf);
        return ret;
    }

    return XQC_OK;
}

xqc_int_t 
xqc_h3_ext_frm_write_bidi_stream_type(xqc_list_head_t *send_buf, 
    uint64_t stream_type, uint8_t fin)
{
    size_t len = xqc_put_varint_len(stream_type);
    xqc_var_buf_t *buf = xqc_var_buf_create(xqc_put_varint_len(XQC_H3_EXT_FRM_BIDI_STREAM_TYPE)
                                            + xqc_put_varint_len(len)
                                            + len);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, XQC_H3_EXT_FRM_BIDI_STREAM_TYPE);
    pos = xqc_put_varint(pos, len);
    pos = xqc_put_varint(pos, stream_type);
    buf->data_len = pos - buf->data;
    buf->fin_flag = fin;

    xqc_int_t ret = xqc_list_buf_to_tail(send_buf, buf);
    if (ret != XQC_OK) {
        xqc_var_buf_free(buf);
        return ret;
    }

    return XQC_OK;
}
