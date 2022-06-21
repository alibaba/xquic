/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/frame/xqc_h3_frame.h"
#include "src/http3/xqc_h3_conn.h"

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
    const unsigned char *pos = p;
    *fin = XQC_FALSE;
    xqc_h3_frame_cancel_push_t *cancel_push = &frame->frame_payload.cancel_push;
    XQC_H3_DECODE_DISCRETE_VINT_VALUE(pos, sz, cancel_push->push_id, fin);
    return pos -p;
}

ssize_t
xqc_h3_frm_parse_settings(const unsigned char *p, size_t sz, xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    const unsigned char *pos = p;
    *fin = XQC_FALSE;
    xqc_h3_frame_settings_t *settings = &frame->frame_payload.settings;
    if (settings->setting == NULL) {
        settings->setting = xqc_var_buf_create(frame->len);
        if (settings->setting == NULL) {
            return -XQC_H3_EMALLOC;
        }
    }

    ssize_t len = xqc_min(sz, frame->len - settings->setting->data_len);
    xqc_int_t ret = xqc_var_buf_save_data(settings->setting, pos, len);
    if (ret != XQC_OK) {
        return ret;
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
        if (push_promise->encoded_field_section == NULL) {
            push_promise->encoded_field_section = xqc_var_buf_create(frame->len - xqc_vint_len_by_val(push_promise->push_id.vi));
            if (push_promise->encoded_field_section == NULL) {
                return -XQC_H3_EMALLOC;
            }
        }
        ssize_t len = xqc_min(sz, frame->len - xqc_vint_len_by_val(push_promise->push_id.vi) - push_promise->encoded_field_section->data_len);
        xqc_int_t ret = xqc_var_buf_save_data(push_promise->encoded_field_section, pos, len);
        if (ret != XQC_OK) {
            return ret;
        }
        pos += len;
        *fin = xqc_vint_len_by_val(push_promise->push_id.vi) + push_promise->encoded_field_section->data_len == frame->len ? XQC_TRUE : XQC_FALSE;
    }
    return pos -p;
}

ssize_t
xqc_h3_frm_parse_goaway(const unsigned char *p, size_t sz, xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    const unsigned char *pos = p;
    *fin = XQC_FALSE;
    xqc_h3_frame_goaway_t *goaway = &frame->frame_payload.goaway;
    XQC_H3_DECODE_DISCRETE_VINT_VALUE(pos, sz, goaway->stream_id, fin);
    return pos -p;
}

ssize_t
xqc_h3_frm_parse_max_push_id(const unsigned char *p, size_t sz, xqc_h3_frame_t *frame, xqc_bool_t *fin)
{
    const unsigned char *pos = p;
    *fin = XQC_FALSE;
    xqc_h3_frame_max_push_id_t *max_push_id = &frame->frame_payload.max_push_id;
    XQC_H3_DECODE_DISCRETE_VINT_VALUE(pos, sz, max_push_id->push_id, fin);
    return pos - p;
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
            xqc_h3_vint_pctx_clear(&pctx->pctx);
            pctx->state = XQC_H3_FRM_STATE_LEN;
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
            xqc_h3_vint_pctx_clear(&pctx->pctx);
            pctx->state = XQC_H3_FRM_STATE_PAYLOAD;
            memset(&pctx->frame.frame_payload, 0, sizeof(xqc_h3_frame_pl_t));
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
    while (data->consumed_len < data->data_len)
    {
        xqc_bool_t fin;
        xqc_discrete_vint_pctx_t identifier, value;
        memset(&identifier, 0, sizeof(xqc_discrete_vint_pctx_t));
        memset(&value, 0, sizeof(xqc_discrete_vint_pctx_t));

        ssize_t read = xqc_discrete_vint_parse(data->data + data->consumed_len, 
                                               data->data_len - data->consumed_len,
                                               &identifier, &fin);
        if (read < 0) {
            return XQC_ERROR;
        }
        data->consumed_len += read;

        read = xqc_discrete_vint_parse(data->data + data->consumed_len,
                                       data->data_len - data->consumed_len, &value, &fin);
        if (read < 0) {
            return XQC_ERROR;
        }
        data->consumed_len += read;

        if (xqc_h3_conn_on_settings_entry_received(identifier.vi, value.vi, user_data) < 0) {
            return XQC_ERROR;
        }
    }

    return XQC_OK;
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
xqc_h3_frm_write_settings(xqc_list_head_t *send_buf, xqc_h3_conn_settings_t *setting, uint8_t fin)
{
    size_t len = 0;
    size_t count = 0;
    xqc_h3_setting_t settings[MAX_SETTING_ENTRY];

    settings[count].identifier.vi = XQC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE;
    settings[count].value.vi = setting->max_field_section_size;
    len += xqc_put_varint_len(settings[count].identifier.vi);
    len += xqc_put_varint_len(settings[count].value.vi);
    ++count;

    settings[count].identifier.vi = XQC_H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY;
    settings[count].value.vi = setting->qpack_max_table_capacity;
    len += xqc_put_varint_len(settings[count].identifier.vi);
    len += xqc_put_varint_len(settings[count].value.vi);
    ++count;

    settings[count].identifier.vi = XQC_H3_SETTINGS_QPACK_BLOCKED_STREAMS;
    settings[count].value.vi = setting->qpack_blocked_streams;
    len += xqc_put_varint_len(settings[count].identifier.vi);
    len += xqc_put_varint_len(settings[count].value.vi);
    ++count;

    xqc_var_buf_t *buf = xqc_var_buf_create(xqc_put_varint_len(XQC_H3_FRM_SETTINGS)
                                            + xqc_put_varint_len(len)
                                            + len);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, XQC_H3_FRM_SETTINGS);
    pos = xqc_put_varint(pos, len);
    for (int i = 0; i < count; ++i) {
        pos = xqc_put_varint(pos, settings[i].identifier.vi);
        pos = xqc_put_varint(pos, settings[i].value.vi);
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
