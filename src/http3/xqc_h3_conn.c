/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_ctx.h"

#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_client.h"
#include "src/transport/xqc_defs.h"


xqc_h3_conn_settings_t default_local_h3_conn_settings = {
    .max_pushes                 = 0,
    .max_field_section_size     = XQC_H3_MAX_FIELD_SECTION_SIZE,
    .qpack_blocked_streams      = XQC_QPACK_MAX_BLOCK_STREAM,
    .qpack_max_table_capacity   = XQC_QPACK_MAX_TABLE_CAPACITY,
};

xqc_h3_conn_settings_t default_peer_h3_conn_settings = {
    .max_pushes                 = XQC_H3_SETTINGS_UNSET,
    .max_field_section_size     = XQC_H3_SETTINGS_UNSET,
    .qpack_blocked_streams      = XQC_H3_SETTINGS_UNSET,
    .qpack_max_table_capacity   = XQC_H3_SETTINGS_UNSET,
};


/**
 * @brief structure and functions for blocked stream
 */
typedef struct xqc_h3_blocked_stream_s {
    xqc_list_head_t          head;
    xqc_h3_stream_t         *h3s;
    uint64_t                 ricnt;
} xqc_h3_blocked_stream_t;

xqc_h3_blocked_stream_t *
xqc_h3_blocked_stream_create(xqc_h3_stream_t *h3s, uint64_t ricnt)
{
    xqc_h3_blocked_stream_t *blocked_stream = xqc_malloc(sizeof(xqc_h3_blocked_stream_t));
    xqc_init_list_head(&blocked_stream->head);
    blocked_stream->h3s = h3s;
    blocked_stream->ricnt = ricnt;
    return blocked_stream;
}

void
xqc_h3_blocked_stream_free(xqc_h3_blocked_stream_t *blocked_stream)
{
    xqc_list_del(&blocked_stream->head);
    xqc_free(blocked_stream);
}

/* destroy blocked streams and related h3 stream */
void
xqc_h3_conn_destroy_blocked_stream_list(xqc_h3_conn_t *h3c);


/**
 * h3_conn external interfaces
 */
void
xqc_h3_engine_set_dec_max_dtable_capacity(xqc_engine_t *engine, size_t value)
{
    default_local_h3_conn_settings.qpack_max_table_capacity = value;
}

void
xqc_h3_engine_set_enc_max_dtable_capacity(xqc_engine_t *engine, size_t value)
{
    default_local_h3_conn_settings.qpack_max_table_capacity = value;
}

void
xqc_h3_engine_set_max_dtable_capacity(xqc_engine_t *engine, size_t capacity)
{
    default_local_h3_conn_settings.qpack_max_table_capacity = capacity;
}

void
xqc_h3_engine_set_max_field_section_size(xqc_engine_t *engine, size_t size)
{
    default_local_h3_conn_settings.max_field_section_size = size;
}


const xqc_cid_t *
xqc_h3_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    xqc_connection_t *conn;
    conn = xqc_client_connect(engine, conn_settings, token, token_len, server_host, no_crypto_flag, 
                              conn_ssl_config, xqc_h3_alpn[conn_settings->proto_version], peer_addr,
                              peer_addrlen, user_data);
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_client_connect error|");
        return NULL;
    }

    return &conn->scid_set.user_scid;
}


xqc_int_t
xqc_h3_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    return xqc_conn_close(engine, cid);
}


xqc_connection_t *
xqc_h3_conn_get_xqc_conn(xqc_h3_conn_t *h3_conn)
{
    return  XQC_LIKELY(h3_conn) ? h3_conn->conn : NULL;
}


xqc_int_t
xqc_h3_conn_get_errno(xqc_h3_conn_t *h3_conn)
{
    xqc_int_t ret = xqc_conn_get_errno(h3_conn->conn);
    return ret == XQC_OK ? H3_NO_ERROR : ret;
}


void
xqc_h3_conn_set_user_data(xqc_h3_conn_t *h3_conn,
                          void *user_data)
{
    h3_conn->user_data = user_data;
    xqc_conn_set_transport_user_data(h3_conn->conn, user_data);
}


void
xqc_h3_conn_set_settings(xqc_h3_conn_t *h3_conn, const xqc_h3_conn_settings_t *h3_conn_settings)
{
    xqc_h3_conn_settings_t *settings = &h3_conn->local_h3_conn_settings;

    if (h3_conn_settings->max_field_section_size) {
        settings->max_field_section_size = h3_conn_settings->max_field_section_size;
    }

    if (h3_conn_settings->max_pushes) {
        settings->max_pushes = h3_conn_settings->max_pushes;
    }

    if (h3_conn_settings->qpack_max_table_capacity) {
        settings->qpack_max_table_capacity = h3_conn_settings->qpack_max_table_capacity;
    }

    if (h3_conn_settings->qpack_blocked_streams) {
        settings->qpack_blocked_streams = h3_conn_settings->qpack_blocked_streams;
    }

    xqc_log_event(h3_conn->log, HTTP_PARAMETERS_SET, h3_conn, XQC_LOG_LOCAL_EVENT);
}


xqc_int_t
xqc_h3_conn_get_peer_addr(xqc_h3_conn_t *h3c, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *peer_addr_len)
{
    return xqc_conn_get_peer_addr(h3c->conn, addr, addr_cap, peer_addr_len);
}


xqc_int_t
xqc_h3_conn_get_local_addr(xqc_h3_conn_t *h3c, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *local_addr_len)
{
    return xqc_conn_get_local_addr(h3c->conn, addr, addr_cap, local_addr_len);
}


xqc_int_t 
xqc_h3_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data)
{
    return xqc_conn_send_ping(engine, cid, ping_user_data);
}


xqc_bool_t
xqc_h3_conn_is_ready_to_send_early_data(xqc_h3_conn_t *h3_conn)
{
    return xqc_conn_is_ready_to_send_early_data(h3_conn->conn);
}


/**
 * h3_conn header file interfaces and related functions
 */

/* used to set qpack dynamic table capacity */
xqc_int_t
xqc_h3_conn_set_qpack_dtable_cap(xqc_h3_conn_t *h3c, size_t capacity)
{
    return xqc_qpack_set_dtable_cap(h3c->qpack, capacity);
}

ssize_t
xqc_h3_conn_send_ins(xqc_qpack_ins_type_t type, xqc_var_buf_t *buf, void *user_data)
{
    if (user_data == NULL) {
        return -XQC_EPARAM;
    }

    xqc_h3_conn_t *h3c = (xqc_h3_conn_t *)user_data;
    ssize_t sent = buf->data_len;

    /* get stream */
    xqc_h3_stream_t *h3s = NULL;
    if (type == XQC_INS_TYPE_ENCODER) {
        h3s = h3c->qenc_stream;

    } else {
        h3s = h3c->qdec_stream;
    }

    /* directly send */
    xqc_int_t ret = xqc_h3_stream_send_buffer(h3s);
    if (ret < 0 && ret != -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_stream_send error|%d|", ret);
        XQC_H3_CONN_ERR(h3c, H3_INTERNAL_ERROR, ret);
    }

    return sent;
}

xqc_var_buf_t *
xqc_h3_conn_get_ins_buf(xqc_qpack_ins_type_t type, void *user_data)
{
    if (user_data == NULL) {
        return NULL;
    }

    xqc_h3_conn_t *h3c = (xqc_h3_conn_t *)user_data;

    /* get stream */
    xqc_h3_stream_t *h3s = NULL;
    if (type == XQC_INS_TYPE_ENCODER) {
        h3s = h3c->qenc_stream;

    } else {
        h3s = h3c->qdec_stream;
    }

    return xqc_h3_stream_get_send_buf(h3s);
}



/* callback for processing instruction buffer */
const xqc_qpack_ins_cb_t xqc_h3_qpack_ins_cb = {
    .get_buf_cb     = xqc_h3_conn_get_ins_buf,
    .write_ins_cb   = xqc_h3_conn_send_ins
};


xqc_int_t
xqc_h3_conn_init_callbacks(xqc_h3_conn_t *h3c)
{
    xqc_h3_callbacks_t *h3_cbs = NULL;
    xqc_int_t ret = xqc_h3_ctx_get_app_callbacks(&h3_cbs);
    if (XQC_OK != ret || h3_cbs == NULL) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|can't get app callbacks, not initialized?");
        return ret;
    }

    h3c->h3_conn_callbacks = h3_cbs->h3c_cbs;

    return XQC_OK;
}


xqc_h3_conn_t *
xqc_h3_conn_create(xqc_connection_t *conn, void *user_data)
{
    xqc_h3_conn_t *h3c = xqc_calloc(1, sizeof(xqc_h3_conn_t));
    if (!h3c) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return NULL;
    }

    h3c->conn = conn;
    h3c->log = conn->log;
    h3c->user_data = user_data;

    h3c->control_stream_out = NULL;

    /* set callback functions from application layer to http3 layer */
    xqc_h3_conn_init_callbacks(h3c);

    h3c->local_h3_conn_settings = default_local_h3_conn_settings;
    h3c->peer_h3_conn_settings = default_peer_h3_conn_settings;

    /* create qpack */
    h3c->qpack = xqc_qpack_create(h3c->local_h3_conn_settings.qpack_max_table_capacity, 
                                  h3c->log, &xqc_h3_qpack_ins_cb, h3c);
    h3c->qdec_stream = NULL;
    h3c->qenc_stream = NULL;

    /* blocked streams list */
    xqc_init_list_head(&h3c->block_stream_head);
    h3c->block_stream_count = 0;

    /* creation callback */
    if (h3c->h3_conn_callbacks.h3_conn_create_notify) {
        if (h3c->h3_conn_callbacks.h3_conn_create_notify(h3c, &h3c->conn->scid_set.user_scid, user_data)) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|h3_conn_create_notify failed|");
            goto fail;
        }

        h3c->flags |= XQC_H3_CONN_FLAG_UPPER_CONN_EXIST;
    }

    /* set ALPN user_data */
    xqc_conn_set_alp_user_data(conn, h3c);

    return h3c;

fail:
    xqc_h3_conn_destroy(h3c);
    return NULL;
}

void
xqc_h3_conn_destroy(xqc_h3_conn_t *h3_conn)
{
    if (h3_conn->h3_conn_callbacks.h3_conn_close_notify
        && (h3_conn->flags & XQC_H3_CONN_FLAG_UPPER_CONN_EXIST))
    {
        h3_conn->h3_conn_callbacks.h3_conn_close_notify(h3_conn, &h3_conn->conn->scid_set.user_scid,
                                                        h3_conn->user_data);
        h3_conn->flags &= ~XQC_H3_CONN_FLAG_UPPER_CONN_EXIST;
    }

    xqc_h3_conn_destroy_blocked_stream_list(h3_conn);
    xqc_qpack_destroy(h3_conn->qpack);

    xqc_log(h3_conn->log, XQC_LOG_DEBUG, "|success|");
    xqc_free(h3_conn);
}


xqc_int_t
xqc_h3_conn_on_uni_stream_created(xqc_h3_conn_t *h3c, uint64_t stype)
{
    uint64_t cflag;
    static const uint64_t stype_2_flag_map[] = {
        [XQC_H3_STREAM_TYPE_CONTROL]        = XQC_H3_CONN_FLAG_CONTROL_OPENED,
        [XQC_H3_STREAM_TYPE_PUSH]           = XQC_H3_CONN_FLAG_PUSH_OPENED,
        [XQC_H3_STREAM_TYPE_QPACK_ENCODER]  = XQC_H3_CONN_FLAG_QPACK_ENCODER_OPENED,
        [XQC_H3_STREAM_TYPE_QPACK_DECODER]  = XQC_H3_CONN_FLAG_QPACK_DECODER_OPENED,
    };

    /* check if control and qpack streams are already created */
    switch (stype) {
    case XQC_H3_STREAM_TYPE_CONTROL:
    case XQC_H3_STREAM_TYPE_PUSH:
    case XQC_H3_STREAM_TYPE_QPACK_ENCODER:
    case XQC_H3_STREAM_TYPE_QPACK_DECODER:
        cflag = stype_2_flag_map[stype];   /* stream creation flag */
        /* if control/encoder/decoder stream has been created, close connection */
        if (h3c->flags & cflag) {
            xqc_log(h3c->log, XQC_LOG_ERROR,
                    "|h3 uni-stream has been created|type:%ui|", stype);

            XQC_H3_CONN_ERR(h3c, H3_FRAME_ERROR, -XQC_H3_INVALID_STREAM);
            return -XQC_H3_INVALID_STREAM;
        }

        h3c->flags |= cflag;
        break;

    default:
        /* reserved stream type, do nothing */
        break;
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_conn_send_settings(xqc_h3_conn_t *h3c)
{
    xqc_h3_conn_settings_t *settings = &h3c->local_h3_conn_settings;
    xqc_int_t ret = xqc_h3_stream_send_setting(h3c->control_stream_out, settings, 0);
    if (ret != XQC_OK) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_write_settings error|%d|", ret);
        return ret;
    }

    xqc_log(h3c->log, XQC_LOG_DEBUG, "|write settings success|qpack_blocked_streams:%ui|"
            "qpack_max_table_capacity:%ui|max_field_section_size:%ui|max_pushes:%ui|",
            settings->qpack_blocked_streams, settings->qpack_max_table_capacity,
            settings->max_field_section_size, settings->max_pushes);

    return XQC_OK;
}


xqc_h3_stream_t *
xqc_h3_conn_create_uni_stream(xqc_h3_conn_t *h3c, xqc_h3_stream_type_t h3s_type)
{
    xqc_h3_stream_t *h3s = NULL;
    /* get stream type */
    xqc_stream_type_t stream_type;
    if (h3c->conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        stream_type = XQC_CLI_UNI;

    } else {
        stream_type = XQC_SVR_UNI;
    }

    /* create transport stream */
    xqc_stream_t *stream = xqc_create_stream_with_conn(
        h3c->conn, XQC_UNDEFINE_STREAM_ID, stream_type, NULL);
    if (!stream) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_create_stream_with_conn error|type:%d|", h3s_type);
        goto error;
    }

    /* create h3 stream */
    h3s = xqc_h3_stream_create(h3c, stream, h3s_type, NULL);
    if (NULL == h3s) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_create error|type:%d|", h3s_type);
        goto error;
    }

    /* send h3 stream type */
    if (xqc_h3_stream_send_uni_stream_hdr(h3s) != XQC_OK) {
        xqc_log(h3c->log, XQC_LOG_ERROR, 
                "|write h3 uni-stream type error|type:%d|", h3s_type);
        goto error;
    }

    xqc_log(h3c->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|stream_type:%d|",
            stream->stream_id, h3s_type);

    return h3s;

error:
    if (NULL != h3s) {
        xqc_h3_stream_destroy(h3s);
    }

    if (stream) {
        xqc_destroy_stream(stream);
    }

    return NULL;
}


xqc_bool_t
xqc_h3_conn_is_goaway_recved(xqc_h3_conn_t *h3c, uint64_t stream_id)
{
    if (h3c->flags & XQC_H3_CONN_FLAG_GOAWAY_RECVD && stream_id >= h3c->goaway_stream_id) {
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

xqc_int_t
xqc_h3_conn_on_settings_entry_received(uint64_t identifier, uint64_t value, void *user_data)
{
    xqc_int_t ret;
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t *) user_data;

    xqc_log(h3c->log, XQC_LOG_DEBUG, "|id:%ui|value:%ui|", identifier, value);
    xqc_log_event(h3c->log, HTTP_SETTING_PARSED, identifier, value);

    switch (identifier) {
    case XQC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
        h3c->peer_h3_conn_settings.max_field_section_size = value;
        break;

    case XQC_H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
        h3c->peer_h3_conn_settings.qpack_max_table_capacity = value;

        /* 
         * set peer's max dtable cap of decoder to qpack's encoder, 
         * which is essential when encoding Required Insert Count 
         */
        ret = xqc_qpack_set_enc_max_dtable_cap(h3c->qpack, value);
        if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|set max dtable capacity error|ret:%d", ret);
            return ret;
        }

        /* dtable cap is the actual size set on local */
        ret = xqc_qpack_set_dtable_cap(h3c->qpack, xqc_min(
            value, h3c->local_h3_conn_settings.qpack_max_table_capacity));
        if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|set dtable capacity error|ret:%d", ret);
            return ret;
        }

        break;

    case XQC_H3_SETTINGS_QPACK_BLOCKED_STREAMS:
        h3c->peer_h3_conn_settings.qpack_blocked_streams = value;
        ret = xqc_qpack_set_max_blocked_stream(h3c->qpack, value);
        if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|set qpack blocked stream error|ret:%d", ret);
            return ret;
        }
        break;

    default:
        xqc_log(h3c->log, XQC_LOG_INFO, "|ignore unknown setting|identifier%ui|value:%ui",
                identifier, value);
        break;
    }

    return XQC_OK;
}

xqc_qpack_t *
xqc_h3_conn_get_qpack(xqc_h3_conn_t *h3c)
{
    return h3c->qpack;
}


xqc_h3_blocked_stream_t *
xqc_h3_conn_add_blocked_stream(xqc_h3_conn_t *h3c, xqc_h3_stream_t *h3s, uint64_t ric)
{
    if (h3c->block_stream_count == h3c->local_h3_conn_settings.qpack_blocked_streams) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|exceed max blocked stream limit|limit:%ui",
                h3c->local_h3_conn_settings.qpack_blocked_streams);
        return NULL;
    }

    xqc_h3_blocked_stream_t *blocked_stream = xqc_h3_blocked_stream_create(h3s, ric);

    /* insert into list order by required insert count asc */
    xqc_list_head_t *pos, *next;
    xqc_h3_blocked_stream_t *bs;
    xqc_list_for_each_safe(pos, next, &h3c->block_stream_head) {
        bs = xqc_list_entry(pos, xqc_h3_blocked_stream_t, head);
        if (bs->ricnt > ric) {
            break;
        }
    }

    xqc_list_add_tail(&blocked_stream->head, pos);
    h3c->block_stream_count++;

    return blocked_stream;
}

void
xqc_h3_conn_remove_blocked_stream(xqc_h3_conn_t *h3c, xqc_h3_blocked_stream_t *blocked_stream)
{
    xqc_h3_blocked_stream_free(blocked_stream);
    h3c->block_stream_count--;
}

void
xqc_h3_conn_destroy_blocked_stream_list(xqc_h3_conn_t *h3c)
{
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &h3c->block_stream_head) {
        xqc_h3_blocked_stream_t *blocked_stream =
                xqc_list_entry(pos, xqc_h3_blocked_stream_t, head);

        /**
         * when destroying h3 connection, and a h3 stream is still blocked, it means that Transport
         * stream was destroyed while h3 stream is still waiting for encoder instructions, but
         * connection was closed actively or some reason else.
         */
        xqc_h3_stream_t *h3s = blocked_stream->h3s;
        xqc_h3_stream_destroy(h3s);
    }
}

xqc_int_t
xqc_h3_conn_process_blocked_stream(xqc_h3_conn_t *h3c)
{
    uint64_t known_received_count = xqc_qpack_get_dec_insert_count(h3c->qpack);
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &h3c->block_stream_head) {
        xqc_h3_blocked_stream_t *blocked_stream = 
            xqc_list_entry(pos, xqc_h3_blocked_stream_t, head);
        if (blocked_stream->ricnt <= known_received_count) {
            xqc_int_t ret = xqc_h3_stream_process_blocked_stream(blocked_stream->h3s);
            if (ret < 0) {
                return ret;
            }

        } else {
            break;
        }
    }
    return XQC_OK;
}


xqc_int_t
xqc_h3_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    xqc_int_t ret;
    xqc_h3_conn_t *h3c;
    h3c = xqc_h3_conn_create(conn, user_data);
    if (!h3c) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_h3_conn_create error|");
        return -XQC_H3_ECREATE_CONN;
    }

    /* control local stream */
    h3c->control_stream_out = xqc_h3_conn_create_uni_stream(h3c, XQC_H3_STREAM_TYPE_CONTROL);
    if (NULL == h3c->control_stream_out) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|create control stream error|");
        return XQC_ERROR;
    }

    /* qpack encoder stream */
    h3c->qenc_stream = xqc_h3_conn_create_uni_stream(h3c, XQC_H3_STREAM_TYPE_QPACK_ENCODER);
    if (NULL == h3c->qenc_stream) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|create qpack encoder stream error|");
        return XQC_ERROR;
    }

    /* qpack decoder stream */
    h3c->qdec_stream = xqc_h3_conn_create_uni_stream(h3c, XQC_H3_STREAM_TYPE_QPACK_DECODER);
    if (NULL == h3c->qdec_stream) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|create qpack decoder stream error|");
        return XQC_ERROR;
    }

    /* send SETTINGS */
    ret = xqc_h3_conn_send_settings(h3c);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_h3_conn_send_settings error|");
        return ret;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|create h3 conn success|");
    return XQC_OK;
}


xqc_int_t
xqc_h3_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t*)user_data;
    xqc_h3_conn_destroy(h3c);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|destroy h3 conn success|");
    return XQC_OK;
}


void
xqc_h3_conn_handshake_finished(xqc_connection_t *conn, void *user_data)
{
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t*)user_data;
    if (h3c->h3_conn_callbacks.h3_conn_handshake_finished) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|HANDSHAKE_COMPLETED notify|");

        h3c->h3_conn_callbacks.h3_conn_handshake_finished(h3c, h3c->user_data);
    }
}

void
xqc_h3_conn_ping_acked_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data,
    void *user_data)
{
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t*)user_data;

    if (h3c->h3_conn_callbacks.h3_conn_ping_acked) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|Ping acked notify|");

        h3c->h3_conn_callbacks.h3_conn_ping_acked(h3c, &h3c->conn->scid_set.user_scid,
                                                  ping_user_data, h3c->user_data);
    }
}


/* HTTP/3 layer connection and streams callback over Transport-Layer */
const xqc_conn_callbacks_t h3_conn_callbacks = {
    .conn_create_notify         = xqc_h3_conn_create_notify,
    .conn_close_notify          = xqc_h3_conn_close_notify,
    .conn_handshake_finished    = xqc_h3_conn_handshake_finished,
    .conn_ping_acked            = xqc_h3_conn_ping_acked_notify,
};
