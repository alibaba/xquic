#include "moq/moq_transport/xqc_moq_datagram.h"
#include "src/transport/xqc_conn.h"
#include "moq/moq_transport/xqc_moq_session.h"

static void xqc_moq_quic_dgram_read_notify(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t unix_ts);
static void xqc_moq_quic_dgram_write_notify(xqc_connection_t *conn, void *user_data);
static void xqc_moq_quic_dgram_acked_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data);
static void xqc_moq_quic_dgram_lost_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data);

const xqc_datagram_callbacks_t xqc_moq_quic_dgram_callbacks = {
    .datagram_read_notify  = xqc_moq_quic_dgram_read_notify,
    // .datagram_write_notify = xqc_moq_quic_dgram_write_notify,
    // .datagram_acked_notify = xqc_moq_quic_dgram_acked_notify,
    // .datagram_lost_notify  = xqc_moq_quic_dgram_lost_notify,
};

static xqc_bool_t
xqc_moq_datagram_type_has_extensions(uint64_t type)
{
    // LSB 位决定是否包含扩展头：0x1 和 0x3 包含扩展头
    return (type & 0x01) != 0;
}

static xqc_bool_t
xqc_moq_datagram_type_is_end_of_group(uint64_t type)
{
    // Type 0x2 和 0x3 表示 End of Group
    return (type == XQC_MOQ_OBJECT_DATAGRAM_EOG || type == XQC_MOQ_OBJECT_DATAGRAM_EOG_EXT);
}

static xqc_bool_t
xqc_moq_datagram_type_is_status(uint64_t type)
{
    // Type 0x4-0x5 是 OBJECT_DATAGRAM_STATUS
    return (type == XQC_MOQ_OBJECT_DATAGRAM_STATUS || type == XQC_MOQ_OBJECT_DATAGRAM_STATUS_EXT);
}

xqc_int_t
xqc_moq_datagram_decode(uint8_t *buf, size_t buf_len, xqc_moq_object_datagram_t *object_datagram)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t type = 0;
    uint64_t priority = 0;

    // 初始化结构 
    xqc_memset(object_datagram, 0, sizeof(xqc_moq_object_datagram_t));

    // 解析 Type 字段 
    ret = xqc_vint_read(buf + processed, buf + buf_len, &type);
    if (ret < 0) {
        return ret;
    }
    processed += ret;

    // 验证 Type 是否为有效的 OBJECT_DATAGRAM 类型 (0x0-0x3)
    if (type > XQC_MOQ_OBJECT_DATAGRAM_EOG_EXT) {
        return -XQC_EILLEGAL_FRAME;
    }

    object_datagram->type = type;
    object_datagram->extensions_present = xqc_moq_datagram_type_has_extensions(type);
    object_datagram->end_of_group = xqc_moq_datagram_type_is_end_of_group(type);

    // 解析 Track Alias 
    ret = xqc_vint_read(buf + processed, buf + buf_len, &object_datagram->track_alias);
    if (ret < 0) {
        return ret;
    }
    processed += ret;

    // 解析 Group ID 
    ret = xqc_vint_read(buf + processed, buf + buf_len, &object_datagram->group_id);
    if (ret < 0) {
        return ret;
    }
    processed += ret;

    // 解析 Object ID 
    ret = xqc_vint_read(buf + processed, buf + buf_len, &object_datagram->object_id);
    if (ret < 0) {
        return ret;
    }
    processed += ret;

    // 解析 Publisher Priority 
    ret = xqc_vint_read(buf + processed, buf + buf_len, &priority);
    if (ret < 0) {
        return ret;
    }
    object_datagram->publisher_priority = (uint8_t)priority;
    processed += ret;

    // 解析 Extension Headers（仅当 Extensions Present 时） 
    if (object_datagram->extensions_present) {
        ret = xqc_vint_read(buf + processed, buf + buf_len, &object_datagram->extension_headers_length);
        if (ret < 0) {
            return ret;
        }
        processed += ret;

        // 根据标准，如果有 Extensions Present的情况下
        // 但没有Extension Headers Length，应该报协议违规 
        if (object_datagram->extension_headers_length == 0) {
            return -XQC_EPROTO;
        }

        if (object_datagram->extension_headers_length > 0) {
            if (processed + object_datagram->extension_headers_length > buf_len) {
                return -XQC_EPROTO;
            }
            object_datagram->extension_headers = (uint8_t *)xqc_malloc(object_datagram->extension_headers_length);
            if (object_datagram->extension_headers == NULL) {
                return -XQC_EMALLOC;
            }
            xqc_memcpy(object_datagram->extension_headers, buf + processed, object_datagram->extension_headers_length);
            processed += object_datagram->extension_headers_length;
        }
    }

    // 解析 Object Payload（OBJECT_DATAGRAM 总是包含 payload）
    object_datagram->payload_len = buf_len - processed;
    if (object_datagram->payload_len > 0) {
        object_datagram->payload = (uint8_t *)xqc_malloc(object_datagram->payload_len);
        if (object_datagram->payload == NULL) {
            if (object_datagram->extension_headers) {
                xqc_free(object_datagram->extension_headers);
            }
            return -XQC_EMALLOC;
        }
        xqc_memcpy(object_datagram->payload, buf + processed, object_datagram->payload_len);
    }

    return XQC_OK;
}

xqc_int_t
xqc_moq_datagram_status_decode(uint8_t *buf, size_t buf_len, xqc_moq_object_datagram_status_t *object_datagram_status)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t type = 0;
    uint64_t priority = 0;

    xqc_memset(object_datagram_status, 0, sizeof(xqc_moq_object_datagram_status_t));

    // 解析 Type 字段 
    ret = xqc_vint_read(buf + processed, buf + buf_len, &type);
    if (ret < 0) {
        return ret;
    }
    processed += ret;

    // 验证 Type 是否为 STATUS 类型 (0x4-0x5)
    if (type != XQC_MOQ_OBJECT_DATAGRAM_STATUS && type != XQC_MOQ_OBJECT_DATAGRAM_STATUS_EXT) {
        return -XQC_EILLEGAL_FRAME;
    }

    object_datagram_status->type = type;
    object_datagram_status->extensions_present = xqc_moq_datagram_type_has_extensions(type);

    // 解析公共字段 
    ret = xqc_vint_read(buf + processed, buf + buf_len, &object_datagram_status->track_alias);
    if (ret < 0) return ret;
    processed += ret;

    ret = xqc_vint_read(buf + processed, buf + buf_len, &object_datagram_status->group_id);
    if (ret < 0) return ret;
    processed += ret;

    ret = xqc_vint_read(buf + processed, buf + buf_len, &object_datagram_status->object_id);
    if (ret < 0) return ret;
    processed += ret;

    ret = xqc_vint_read(buf + processed, buf + buf_len, &priority);
    if (ret < 0) return ret;
    object_datagram_status->publisher_priority = (uint8_t)priority;
    processed += ret;

    // 解析 Extension Headers（仅当 Extensions 存在时）
    if (object_datagram_status->extensions_present) {
        ret = xqc_vint_read(buf + processed, buf + buf_len, &object_datagram_status->extension_headers_length);
        if (ret < 0) return ret;
        processed += ret;

        // 根据标准，如果有 Extensions Present = Yes 
        // 但 Extension Headers Length = 0，应该报协议违规
        if (object_datagram_status->extension_headers_length == 0) {
            return -XQC_EPROTO;
        }

        if (object_datagram_status->extension_headers_length > 0) {
            if (processed + object_datagram_status->extension_headers_length > buf_len) {
                return -XQC_EPROTO;
            }
            object_datagram_status->extension_headers = (uint8_t *)xqc_malloc(object_datagram_status->extension_headers_length);
            if (object_datagram_status->extension_headers == NULL) {
                return -XQC_EMALLOC;
            }
            xqc_memcpy(object_datagram_status->extension_headers, buf + processed, object_datagram_status->extension_headers_length);
            processed += object_datagram_status->extension_headers_length;
        }
    }

    // 解析 Object Status 
    ret = xqc_vint_read(buf + processed, buf + buf_len, &object_datagram_status->object_status);
    if (ret < 0) {
        if (object_datagram_status->extension_headers) {
            xqc_free(object_datagram_status->extension_headers);
        }
        return ret;
    }

    return XQC_OK;
}

void xqc_moq_quic_dgram_read_notify(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t unix_ts)
{
    xqc_moq_user_session_t *user_session = xqc_conn_get_user_data(conn);
    if (user_session == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|user session is NULL|");
        return;
    }
    xqc_moq_session_t *session = user_session->session;

    // 首先读取 Type 字段来判断消息类型 
    uint64_t type = 0;
    xqc_int_t ret = xqc_vint_read((uint8_t *)data, (uint8_t *)data + data_len, &type);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|failed to read datagram type|ret:%d|", ret);
        return;
    }

    if (xqc_moq_datagram_type_is_status(type)) {
        // 处理 OBJECT_DATAGRAM_STATUS 
        xqc_moq_object_datagram_status_t *dgram_status = (xqc_moq_object_datagram_status_t *)xqc_malloc(sizeof(xqc_moq_object_datagram_status_t));
        if (dgram_status == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|malloc failed for datagram status|");
            return;
        }

        ret = xqc_moq_datagram_status_decode((uint8_t *)data, data_len, dgram_status);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_moq_datagram_status_decode error|ret:%d|", ret);
            xqc_free(dgram_status);
            return;
        }

        xqc_log(conn->log, XQC_LOG_INFO, "on object datagram status: track_alias:%"PRIu64", group_id:%"PRIu64", object_id:%"PRIu64", status:%"PRIu64"\n",
                dgram_status->track_alias, dgram_status->group_id, dgram_status->object_id, dgram_status->object_status);

        if (session->session_callbacks.on_datagram_status != NULL) {
            session->session_callbacks.on_datagram_status(session->user_session, dgram_status);
        }
        xqc_moq_msg_free_object_datagram_status(dgram_status);

    } else {
        // 处理 OBJECT_DATAGRAM 
        xqc_moq_object_datagram_t *dgram = (xqc_moq_object_datagram_t *)xqc_malloc(sizeof(xqc_moq_object_datagram_t));
        if (dgram == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|malloc failed for datagram|");
            return;
        }

        ret = xqc_moq_datagram_decode((uint8_t *)data, data_len, dgram);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_moq_datagram_decode error|ret:%d|", ret);
            xqc_free(dgram);
            return;
        }

        xqc_log(conn->log, XQC_LOG_INFO, "on object datagram: track_alias:%"PRIu64", group_id:%"PRIu64", object_id:%"PRIu64", priority:%d, payload_len:%zu, end_of_group:%d\n",
                dgram->track_alias, dgram->group_id, dgram->object_id,
                dgram->publisher_priority, dgram->payload_len, dgram->end_of_group);

        if (session->session_callbacks.on_datagram != NULL) {
            session->session_callbacks.on_datagram(session->user_session, dgram);
        }
        xqc_moq_msg_free_object_datagram(dgram);
    }
}
