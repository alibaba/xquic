/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <xquic/xquic.h>
#include "src/transport/xqc_engine.h"
#include "src/common/xqc_str.h"
#include "src/common/xqc_random.h"
#include "src/common/xqc_priority_q.h"
#include "src/common/xqc_str_hash.h"
#include "src/common/xqc_timer.h"
#include "src/common/xqc_hash.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_wakeup_pq.h"
#include "src/transport/xqc_utils.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/tls/xqc_tls.h"


extern const xqc_qpack_ins_cb_t xqc_h3_qpack_ins_cb;

xqc_config_t default_client_config = {
    .cfg_log_level             = XQC_LOG_WARN,
    .cfg_log_event             = 1,
    .cfg_log_timestamp         = 1,
    .cfg_log_level_name        = 1,
    .conn_pool_size            = 4096,
    .streams_hash_bucket_size  = 1024,
    .conns_hash_bucket_size    = 1024,
    .conns_active_pq_capacity  = 128,
    .conns_wakeup_pq_capacity  = 128,
    .support_version_count     = 1,
    .support_version_list[0]   = XQC_VERSION_V1_VALUE,
    .cid_len                   = XQC_DEFAULT_CID_LEN,
    .cid_negotiate             = 0,
    .reset_token_key           = {0},
    .reset_token_keylen        = 0,
    .sendmmsg_on               = 0,
};


xqc_config_t default_server_config = {
    .cfg_log_level             = XQC_LOG_WARN,
    .cfg_log_event             = 1,
    .cfg_log_timestamp         = 1,
    .cfg_log_level_name        = 1,
    .conn_pool_size            = 4096,
    .streams_hash_bucket_size  = 1024,
    .conns_hash_bucket_size    = 1024*1024, /* too many connections will affect lookup performance */
    .conns_active_pq_capacity  = 1024,
    .conns_wakeup_pq_capacity  = 16*1024,
    .support_version_count     = 2,
    .support_version_list      = {XQC_VERSION_V1_VALUE, XQC_IDRAFT_VER_29_VALUE},
    .cid_len                   = XQC_DEFAULT_CID_LEN,
    .cid_negotiate             = 0,
    .reset_token_key           = {0},
    .reset_token_keylen        = 0,
    .sendmmsg_on               = 0,
};


void
xqc_engine_free_alpn_list(xqc_engine_t *engine);


xqc_int_t
xqc_set_config(xqc_config_t *dst, const xqc_config_t *src)
{
    if (src->conn_pool_size > 0) {
        dst->conn_pool_size = src->conn_pool_size;
    }

    if (src->streams_hash_bucket_size > 0) {
        dst->streams_hash_bucket_size = src->streams_hash_bucket_size;
    }

    if (src->conns_hash_bucket_size > 0) {
        dst->conns_hash_bucket_size = src->conns_hash_bucket_size;
    }

    if (src->conns_active_pq_capacity > 0) {
        dst->conns_active_pq_capacity = src->conns_active_pq_capacity;
    }

    if (src->conns_wakeup_pq_capacity > 0) {
        dst->conns_wakeup_pq_capacity = src->conns_wakeup_pq_capacity;
    }

    if (src->support_version_count > 0 && src->support_version_count <= XQC_SUPPORT_VERSION_MAX) {
        dst->support_version_count = src->support_version_count;
        for (int i = 0; i < src->support_version_count; ++i) {
            dst->support_version_list[i] = src->support_version_list[i];
        }

    } else if (src->support_version_count > XQC_SUPPORT_VERSION_MAX) {
        return XQC_ERROR;
    }

    if (src->cid_len > 0 && src->cid_len <= XQC_MAX_CID_LEN) {
        dst->cid_len = src->cid_len;

    } else if (src->cid_len > XQC_MAX_CID_LEN) {
        return XQC_ERROR;
    }

    if (src->reset_token_keylen > 0 && src->reset_token_keylen <= XQC_RESET_TOKEN_MAX_KEY_LEN) {
        dst->reset_token_keylen = src->reset_token_keylen;
        memcpy(dst->reset_token_key, src->reset_token_key, src->reset_token_keylen);
    }

    dst->cid_negotiate = src->cid_negotiate;
    dst->cfg_log_level = src->cfg_log_level;
    dst->cfg_log_event = src->cfg_log_event;
    dst->cfg_log_timestamp = src->cfg_log_timestamp;
    dst->cfg_log_level_name = src->cfg_log_level_name;
    dst->sendmmsg_on = src->sendmmsg_on;

    return XQC_OK;
}


xqc_int_t
xqc_engine_get_default_config(xqc_config_t *config, xqc_engine_type_t engine_type)
{
    if (engine_type == XQC_ENGINE_SERVER) {
        return xqc_set_config(config, &default_server_config);

    } else {
        return xqc_set_config(config, &default_client_config);
    }
}


xqc_int_t
xqc_engine_set_config(xqc_engine_t *engine, const xqc_config_t *engine_config)
{
    return xqc_set_config(engine->config, engine_config);
}


xqc_config_t *
xqc_engine_config_create(xqc_engine_type_t engine_type)
{
    xqc_config_t *config = xqc_malloc(sizeof(xqc_config_t));
    if (config == NULL) {
        return NULL;
    }

    xqc_memzero(config, sizeof(xqc_config_t));

    if (engine_type == XQC_ENGINE_SERVER) {
        xqc_set_config(config, &default_server_config);

    } else if (engine_type == XQC_ENGINE_CLIENT) {
        xqc_set_config(config, &default_client_config);
    }

    return config;
}


void
xqc_engine_config_destroy(xqc_config_t *config)
{
    xqc_free(config);
}


void
xqc_engine_set_log_level(xqc_engine_t *engine, xqc_log_level_t log_level)
{
    xqc_log_level_set(engine->log, log_level);
}


xqc_str_hash_table_t *
xqc_engine_conns_hash_create(xqc_config_t *config)
{
    xqc_str_hash_table_t *hash_table = xqc_malloc(sizeof(xqc_str_hash_table_t));
    if (hash_table == NULL) {
        return NULL;
    }

    if (xqc_str_hash_init(hash_table, xqc_default_allocator, config->conns_hash_bucket_size)) {
        goto fail;
    }

    return hash_table;

fail:
    xqc_str_hash_release(hash_table);
    xqc_free(hash_table);
    return NULL;
}


void
xqc_engine_conns_hash_destroy(xqc_str_hash_table_t *hash_table)
{
    xqc_str_hash_release(hash_table);
    xqc_free(hash_table);
}


xqc_pq_t *
xqc_engine_conns_pq_create(xqc_config_t *config)
{
    xqc_pq_t *q = xqc_malloc(sizeof(xqc_pq_t));
    if (q == NULL) {
        return NULL;
    }

    xqc_memzero(q, sizeof(xqc_pq_t));
    if (xqc_pq_init(q, sizeof(xqc_conns_pq_elem_t),
        config->conns_active_pq_capacity, xqc_default_allocator, xqc_pq_revert_cmp))
    {
        goto fail;
    }

    return q;

fail:
    xqc_pq_destroy(q);
    xqc_free(q);
    return NULL;
}


xqc_wakeup_pq_t *
xqc_engine_wakeup_pq_create(xqc_config_t *config)
{
    xqc_wakeup_pq_t *q = xqc_malloc(sizeof(xqc_wakeup_pq_t));
    if (q == NULL) {
        return NULL;
    }

    xqc_memzero(q, sizeof(xqc_wakeup_pq_t));

    if (xqc_wakeup_pq_init(q, config->conns_wakeup_pq_capacity,
                           xqc_default_allocator, xqc_wakeup_pq_revert_cmp))
    {
        goto fail;
    }

    return q;

fail:
    xqc_wakeup_pq_destroy(q);
    xqc_free(q);
    return NULL;
}


xqc_connection_t *
xqc_engine_conns_hash_find(xqc_engine_t *engine, const xqc_cid_t *cid, char type)
{
    if (cid == NULL || cid->cid_len == 0) {
        return NULL;
    }

    uint64_t hash = xqc_hash_string(cid->cid_buf, cid->cid_len);
    xqc_str_t str;
    str.data = (unsigned char *)cid->cid_buf;
    str.len = cid->cid_len;

    if (type == 's') {
        /* search by endpoint's cid */
        return xqc_str_hash_find(engine->conns_hash, hash, str);

    } else {
        /* search by peer's cid */
        return xqc_str_hash_find(engine->conns_hash_dcid, hash, str);
    }
}


void
xqc_engine_conns_pq_destroy(xqc_pq_t *q)
{
    xqc_pq_destroy(q);
    xqc_free(q);
}

void
xqc_engine_wakeup_pq_destroy(xqc_wakeup_pq_t *q)
{
    xqc_wakeup_pq_destroy(q);
    xqc_free(q);
}


xqc_usec_t
xqc_engine_wakeup_after(xqc_engine_t *engine)
{
    xqc_wakeup_pq_elem_t *el = xqc_wakeup_pq_top(engine->conns_wait_wakeup_pq);
    if (el) {
        xqc_usec_t now = xqc_monotonic_timestamp();
        return el->wakeup_time > now ? el->wakeup_time - now : 1;
    }

    return 0;
}


xqc_int_t
xqc_engine_schedule_reset(xqc_engine_t *engine,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, xqc_usec_t now)
{
    /* Can send 2 reset packets in 5 seconds */
    if (now - engine->reset_sent_cnt_cleared > 5000 * 1000) {
        memset(engine->reset_sent_cnt, 0, sizeof(engine->reset_sent_cnt));
        engine->reset_sent_cnt_cleared = now;
    }

    uint32_t hash = xqc_murmur_hash2((unsigned char*)peer_addr, peer_addrlen);
    hash = hash % XQC_RESET_CNT_ARRAY_LEN;
    xqc_log(engine->log, XQC_LOG_DEBUG, "|hash:%ud|cnt:%ud|", hash, (unsigned int)engine->reset_sent_cnt[hash]);

    if (engine->reset_sent_cnt[hash] < 2) {
        engine->reset_sent_cnt[hash]++;
        return XQC_OK;
    }

    return XQC_ERROR;
}


void
xqc_engine_set_callback(xqc_engine_t *engine, const xqc_engine_callback_t *engine_callback,
    const xqc_transport_callbacks_t *transport_cbs)
{
    engine->eng_callback = *engine_callback;
    engine->transport_cbs = *transport_cbs;

    if (engine_callback->realtime_ts) {
        xqc_realtime_timestamp = engine_callback->realtime_ts;
    }

    if (engine_callback->monotonic_ts) {
        xqc_monotonic_timestamp = engine_callback->monotonic_ts;
    }
}


/**
 * @brief check the legitimacy of engine config
 */
xqc_bool_t
xqc_engine_check_config(xqc_engine_type_t engine_type, const xqc_config_t *engine_config,
    const xqc_engine_ssl_config_t *ssl_config, const xqc_transport_callbacks_t *transport_cbs)
{
    /* mismatch of sendmmsg_on enable and write_mmsg callback function */
    if (engine_config && engine_config->sendmmsg_on && transport_cbs->write_mmsg == NULL) {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

/**
 * Create new xquic engine.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_engine_t *
xqc_engine_create(xqc_engine_type_t engine_type, 
    const xqc_config_t *engine_config,
    const xqc_engine_ssl_config_t *ssl_config,
    const xqc_engine_callback_t *engine_callback, 
    const xqc_transport_callbacks_t *transport_cbs,
    void *user_data)
{
    xqc_engine_t *engine = NULL;

    /* check input parameter */
    if (xqc_engine_check_config(engine_type, engine_config, ssl_config, transport_cbs)
        == XQC_FALSE)
    {
        return NULL;
    }

    engine = xqc_malloc(sizeof(xqc_engine_t));
    if (engine == NULL) {
        goto fail;
    }
    xqc_memzero(engine, sizeof(xqc_engine_t));

    engine->eng_type = engine_type;

    /* init alpn list */
    xqc_init_list_head(&engine->alpn_reg_list);

    engine->config = xqc_engine_config_create(engine_type);
    if (engine->config == NULL) {
        goto fail;
    }

    if (engine_config != NULL
        && xqc_engine_set_config(engine, engine_config) != XQC_OK) 
    {
        goto fail;
    }

    xqc_engine_set_callback(engine, engine_callback, transport_cbs);
    engine->user_data = user_data;

    engine->log = xqc_log_init(engine->config->cfg_log_level,
                               engine->config->cfg_log_event,
                               engine->config->cfg_log_timestamp,
                               engine->config->cfg_log_level_name,
                               &engine->eng_callback.log_callbacks, engine->user_data);
    if (engine->log == NULL) {
        goto fail;
    }

    engine->rand_generator = xqc_random_generator_create(engine->log);
    if (engine->rand_generator == NULL) {
        goto fail;
    }

    engine->conns_hash = xqc_engine_conns_hash_create(engine->config);
    if (engine->conns_hash == NULL) {
        goto fail;
    }
    engine->conns_hash_dcid = xqc_engine_conns_hash_create(engine->config);
    if (engine->conns_hash_dcid == NULL) {
        goto fail;
    }

    engine->conns_active_pq = xqc_engine_conns_pq_create(engine->config);
    if (engine->conns_active_pq == NULL) {
        goto fail;
    }

    engine->conns_wait_wakeup_pq = xqc_engine_wakeup_pq_create(engine->config);
    if (engine->conns_wait_wakeup_pq == NULL) {
        goto fail;
    }

    /* create tls context */
    if (ssl_config != NULL) {
        engine->tls_ctx = xqc_tls_ctx_create((xqc_tls_type_t)engine->eng_type, ssl_config,
                                             &xqc_conn_tls_cbs, engine->log);
        if (NULL == engine->tls_ctx) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|create tls context error");
            goto fail;
        }

    } else {
        goto fail;
    }

    return engine;

fail:
    xqc_engine_destroy(engine);
    return NULL;
}


xqc_connection_t *
xqc_conns_pq_pop_top_conn(xqc_pq_t *pq)
{
    /* used to traverse conns_pq */
    xqc_conns_pq_elem_t *el = xqc_conns_pq_top(pq);
    if (XQC_UNLIKELY(el == NULL || el->conn == NULL)) {
        xqc_conns_pq_pop(pq);
        return NULL;
    }

    xqc_connection_t *conn = el->conn;
    xqc_conns_pq_pop(pq);
    return conn;
}


void
xqc_engine_destroy(xqc_engine_t *engine)
{
    xqc_connection_t *conn;

    if (engine == NULL) {
        return;
    }

    if (engine->log) {
        xqc_log(engine->log, XQC_LOG_DEBUG, "|begin|");
    }

    xqc_engine_free_alpn_list(engine);

    /* free destroy first, then destroy others */
    if (engine->conns_active_pq) {
        while (!xqc_pq_empty(engine->conns_active_pq)) {
            conn = xqc_conns_pq_pop_top_conn(engine->conns_active_pq);
            if (conn == NULL) {
                if (engine->log) {
                    xqc_log(engine->log, XQC_LOG_ERROR, "|NULL ptr, skip|");
                }
                continue;
            }

            conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
            if (conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP) {
                xqc_wakeup_pq_remove(engine->conns_wait_wakeup_pq, conn);
                conn->conn_flag &= ~XQC_CONN_FLAG_WAIT_WAKEUP;
            }

            xqc_conn_destroy(conn);
        }
    }

    if (engine->conns_wait_wakeup_pq) {
        while (!xqc_wakeup_pq_empty(engine->conns_wait_wakeup_pq)) {
            /* get conn from pq top and pop */
            xqc_wakeup_pq_elem_t *el = xqc_wakeup_pq_top(engine->conns_wait_wakeup_pq);
            if (el == NULL || el->conn == NULL) {
                if (engine->log) {
                    xqc_log(engine->log, XQC_LOG_ERROR, "|NULL ptr, skip|");
                }

                xqc_wakeup_pq_pop(engine->conns_wait_wakeup_pq);
                continue;
            }

            /* get conn first then pop */
            conn = el->conn;
            xqc_wakeup_pq_pop(engine->conns_wait_wakeup_pq);

            conn->conn_flag &= ~XQC_CONN_FLAG_WAIT_WAKEUP;
            xqc_conn_destroy(conn);
        }
    }

    if (engine->conns_active_pq) {
        xqc_engine_conns_pq_destroy(engine->conns_active_pq);
        engine->conns_active_pq = NULL;
    }

    if (engine->conns_wait_wakeup_pq) {
        xqc_engine_wakeup_pq_destroy(engine->conns_wait_wakeup_pq);
        engine->conns_wait_wakeup_pq = NULL;
    }

    if (engine->tls_ctx) {
        xqc_tls_ctx_destroy(engine->tls_ctx);
        engine->tls_ctx = NULL;
    }

    if (engine->config) {
        xqc_engine_config_destroy(engine->config);
        engine->config = NULL;
    }

    if (engine->rand_generator) {
        xqc_random_generator_destroy(engine->rand_generator);
        engine->rand_generator = NULL;
    }

    if (engine->conns_hash) {
        xqc_engine_conns_hash_destroy(engine->conns_hash);
        engine->conns_hash = NULL;
    }

    if (engine->conns_hash_dcid) {
        xqc_engine_conns_hash_destroy(engine->conns_hash_dcid);
        engine->conns_hash_dcid = NULL;
    }

    if (engine->tls_ctx) {
        xqc_tls_ctx_destroy(engine->tls_ctx);
    }

    if (engine->log) {
        xqc_log_release(engine->log);
    }

    xqc_free(engine);
}


xqc_int_t
xqc_engine_send_reset(xqc_engine_t *engine, xqc_cid_t *dcid, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    unsigned char buf[XQC_PACKET_OUT_SIZE];
    xqc_int_t size = xqc_gen_reset_packet(dcid, buf,
                                          engine->config->reset_token_key,
                                          engine->config->reset_token_keylen);
    if (size < 0) {
        return size;
    }

    xqc_stateless_reset_pt stateless_cb = engine->transport_cbs.stateless_reset;
    if (stateless_cb) {
        size = (xqc_int_t)stateless_cb(buf, (size_t)size, peer_addr, peer_addrlen, user_data);
        if (size < 0) {
            return size;
        }
    }

    xqc_log(engine->log, XQC_LOG_INFO, "|<==|xqc_engine_send_reset ok|size:%d|", size);
    return XQC_OK;
}


#define XQC_CHECK_UNDECRYPT_PACKETS() do {                      \
    if (XQC_UNLIKELY(xqc_conn_has_undecrypt_packets(conn))) {   \
        xqc_conn_process_undecrypt_packets(conn);               \
        XQC_CHECK_IMMEDIATE_CLOSE();                            \
    }                                                           \
} while(0);                                                     \

#define XQC_CHECK_IMMEDIATE_CLOSE() do {                        \
    if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_IMMEDIATE_CLOSE_FLAGS)) {     \
        xqc_conn_immediate_close(conn);                         \
        goto end;                                               \
    }                                                           \
} while(0);                                                     \


void
xqc_engine_process_conn(xqc_connection_t *conn, xqc_usec_t now)
{
    xqc_log(conn->log, XQC_LOG_DEBUG, "|conn:%p|state:%s|flag:%s|now:%ui|",
            conn, xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag), now);

    int ret;

    xqc_send_ctl_timer_expire(conn->conn_send_ctl, now);

    if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_TIME_OUT)) {
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        return;
    }
    XQC_CHECK_IMMEDIATE_CLOSE();

    if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_LINGER_CLOSING)) {
        if (xqc_send_ctl_out_q_empty(conn->conn_send_ctl)) {
            xqc_conn_log(conn, XQC_LOG_DEBUG, "|out queue empty, close connection|");
            xqc_send_ctl_timer_unset(conn->conn_send_ctl, XQC_TIMER_LINGER_CLOSE);
            xqc_conn_immediate_close(conn);
            conn->conn_flag &= ~XQC_CONN_FLAG_LINGER_CLOSING;
        }
        goto end;
    }

    if (XQC_UNLIKELY(conn->conn_state >= XQC_CONN_STATE_CLOSING)) {
        goto end;
    }

    XQC_CHECK_UNDECRYPT_PACKETS();
    xqc_process_crypto_read_streams(conn);
    XQC_CHECK_UNDECRYPT_PACKETS();
    xqc_process_crypto_write_streams(conn);
    XQC_CHECK_UNDECRYPT_PACKETS();
    XQC_CHECK_IMMEDIATE_CLOSE();

    if (XQC_UNLIKELY(!xqc_list_empty(&conn->conn_send_ctl->ctl_buff_1rtt_packets)
        && conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)) {
        xqc_conn_write_buffed_1rtt_packets(conn);
    }
    XQC_CHECK_IMMEDIATE_CLOSE();

    if (conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT) {
        xqc_process_read_streams(conn);
        if (xqc_send_ctl_can_write(conn->conn_send_ctl)) {
            xqc_process_write_streams(conn);
        } else {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_ctl_can_write false|");
        }
    }
    XQC_CHECK_IMMEDIATE_CLOSE();

    if (xqc_conn_should_ack(conn)) {
        ret = xqc_write_ack_to_packets(conn);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_ack_to_packets error|");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        }
    }
    XQC_CHECK_IMMEDIATE_CLOSE();

    ret = xqc_conn_try_add_new_conn_id(conn, 0);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_try_add_new_conn_id error|");
    }

    /* for multi-path */
    if ((conn->conn_flag & XQC_CONN_FLAG_NEW_CID_RECEIVED)
        && xqc_conn_check_unused_cids(conn) == XQC_OK)
    {
        if (conn->transport_cbs.ready_to_create_path_notify) {
            conn->transport_cbs.ready_to_create_path_notify(&conn->scid_set.user_scid,
                                                            xqc_conn_get_user_data(conn));
        }
        conn->conn_flag &= ~XQC_CONN_FLAG_NEW_CID_RECEIVED;
    }

    if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_PING)) {
        ret = xqc_write_ping_to_packet(conn, NULL, XQC_FALSE);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_ping_to_packet error|");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        }
    }
    XQC_CHECK_IMMEDIATE_CLOSE();

    /* server send version negotiation */
    if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_VERSION_NEGOTIATION)) {
        ret = xqc_conn_send_version_negotiation(conn);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|send version negotiation error|");
        }
    }

end:
    conn->packet_need_process_count = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_NEED_RUN;
    return;
}


void
xqc_engine_recv_batch(xqc_engine_t *engine, xqc_connection_t *conn)
{
    xqc_engine_main_logic_internal(engine, conn);
}


void xqc_engine_finish_recv (xqc_engine_t *engine) {
    xqc_engine_main_logic(engine);
}


void xqc_engine_main_logic_internal(xqc_engine_t *engine, xqc_connection_t *conn) {
    if (conn->conn_flag & XQC_CONN_FLAG_CANNOT_DESTROY) {
        return;
    }

    conn->conn_flag |= XQC_CONN_FLAG_CANNOT_DESTROY;
    xqc_engine_main_logic(engine);
    conn->conn_flag &= ~XQC_CONN_FLAG_CANNOT_DESTROY;
}


/**
 * Process all connections
 */
void
xqc_engine_main_logic(xqc_engine_t *engine)
{
    if (engine->eng_flag & XQC_ENG_FLAG_RUNNING) {
        xqc_log(engine->log, XQC_LOG_DEBUG, "|engine is running|");
        return;
    }
    engine->eng_flag |= XQC_ENG_FLAG_RUNNING;

    xqc_log(engine->log, XQC_LOG_DEBUG, "|");

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_connection_t *conn;

    while (!xqc_wakeup_pq_empty(engine->conns_wait_wakeup_pq)) {
        xqc_wakeup_pq_elem_t *el = xqc_wakeup_pq_top(engine->conns_wait_wakeup_pq);
        if (XQC_UNLIKELY(el == NULL || el->conn == NULL)) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|NULL ptr, skip|");
            xqc_wakeup_pq_pop(engine->conns_wait_wakeup_pq);    /* no push between top and pop */
            continue;
        }
        conn = el->conn;

        /* xqc_log(conn->log, XQC_LOG_DEBUG, "|wakeup|conn:%p|state:%s|flag:%s|now:%ui|wakeup:%ui|",
                conn, xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag), now, el->wakeup_time); */
        if (el->wakeup_time <= now) {
            xqc_wakeup_pq_pop(engine->conns_wait_wakeup_pq);
            conn->conn_flag &= ~XQC_CONN_FLAG_WAIT_WAKEUP;

            if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
                if (0 == xqc_conns_pq_push(engine->conns_active_pq, conn, conn->last_ticked_time)) {
                    conn->conn_flag |= XQC_CONN_FLAG_TICKING;

                } else {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conns_pq_push error|");
                }
            }

        } else {
            break;
        }
    }

    while (!xqc_pq_empty(engine->conns_active_pq)) {
        conn = xqc_conns_pq_pop_top_conn(engine->conns_active_pq);
        if (XQC_UNLIKELY(conn == NULL)) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|NULL ptr, skip|");
            continue;
        }

        xqc_log(conn->log, XQC_LOG_DEBUG, "|ticking|conn:%p|state:%s|flag:%s|now:%ui|",
                conn, xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag), now);

        now = xqc_monotonic_timestamp();
        xqc_engine_process_conn(conn, now);

        if (XQC_UNLIKELY(conn->conn_state == XQC_CONN_STATE_CLOSED)) {
            conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
            if (!(conn->conn_flag & XQC_CONN_FLAG_CANNOT_DESTROY)) {
                xqc_conn_destroy(conn);

            } else {
                if ((conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP)) {
                    xqc_wakeup_pq_remove(engine->conns_wait_wakeup_pq, conn);
                }
                xqc_wakeup_pq_push(engine->conns_wait_wakeup_pq, 0, conn);
                conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;
            }
            continue;

        } else {
            conn->last_ticked_time = now;

            if (xqc_engine_is_sendmmsg_on(engine)) {
                xqc_conn_transmit_pto_probe_packets_batch(conn);
                xqc_conn_retransmit_lost_packets_batch(conn);
                xqc_conn_send_packets_batch(conn);

            } else {
                xqc_conn_transmit_pto_probe_packets(conn);
                xqc_conn_retransmit_lost_packets(conn);
                xqc_conn_send_packets(conn);
            }

            if (XQC_UNLIKELY(conn->conn_state == XQC_CONN_STATE_CLOSED)) {
                conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
                if (!(conn->conn_flag & XQC_CONN_FLAG_CANNOT_DESTROY)) {
                    xqc_conn_destroy(conn);

                } else {
                    if ((conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP)) {
                        xqc_wakeup_pq_remove(engine->conns_wait_wakeup_pq, conn);
                    }
                    xqc_wakeup_pq_push(engine->conns_wait_wakeup_pq, 0, conn);
                    conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;
                }
                continue;
            }

            conn->next_tick_time = xqc_conn_next_wakeup_time(conn);
            if (conn->next_tick_time) {
                if (!(conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP)) {
                    xqc_wakeup_pq_push(engine->conns_wait_wakeup_pq, conn->next_tick_time, conn);
                    conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;

                } else {
                    /* remove from pq then push again, update wakeup time */
                    xqc_wakeup_pq_remove(engine->conns_wait_wakeup_pq, conn);
                    xqc_wakeup_pq_push(engine->conns_wait_wakeup_pq, conn->next_tick_time, conn);
                    conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;
                }

            } else {
                /* it's unexpected that conn's tick timer is unset */
                xqc_log(conn->log, XQC_LOG_ERROR, "|destroy_connection|");
                conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;

                if (!(conn->conn_flag & XQC_CONN_FLAG_CANNOT_DESTROY)) {
                    xqc_conn_destroy(conn);

                } else {
                    if ((conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP)) {
                        xqc_wakeup_pq_remove(engine->conns_wait_wakeup_pq, conn);
                    }
                    xqc_wakeup_pq_push(engine->conns_wait_wakeup_pq, 0, conn);
                    conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;
                }
                continue;
            }
        }

        /*
         * xqc_engine_process_conn may insert conns_active_pq, XQC_CONN_FLAG_TICKING prevents
         * duplicate insertions and must be placed after xqc_engine_process_conn.
         */
        conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
    }

    xqc_usec_t wake_after = xqc_engine_wakeup_after(engine);
    if (wake_after > 0) {
        engine->eng_callback.set_event_timer(wake_after, engine->user_data);
    }

    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    return;
}

/**
 * Pass received UDP packet payload into xquic engine.
 * @param recv_time   UDP packet received time in microsecond
 */
xqc_int_t
xqc_engine_packet_process(xqc_engine_t *engine,
    const unsigned char *packet_in_buf, size_t packet_in_size,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    xqc_usec_t recv_time, void *user_data)
{
    xqc_int_t ret;
    xqc_connection_t *conn = NULL;
    xqc_cid_t dcid, scid;   /* dcid: cid of peer; scid: cid of endpoint */
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    /* reverse packet's dcid/scid to endpoint's scid/dcid */
    ret = xqc_packet_parse_cid(&scid, &dcid, engine->config->cid_len,
                               (unsigned char *)packet_in_buf, packet_in_size);
    if (XQC_UNLIKELY(ret != XQC_OK)) {
        xqc_log(engine->log, XQC_LOG_INFO, "|fail to parse cid|ret:%d|", ret);
        return -XQC_EILLPKT;
    }

    conn = xqc_engine_conns_hash_find(engine, &scid, 's');

    /* server creates connection when receiving a initial packet*/
    if (XQC_UNLIKELY(conn == NULL
                     && engine->eng_type == XQC_ENGINE_SERVER
                     && XQC_PACKET_IS_LONG_HEADER(packet_in_buf)
                     && (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in_buf) == XQC_PTYPE_INIT
                         || XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in_buf) == XQC_PTYPE_0RTT)
                     && (local_addr != NULL && peer_addr != NULL)))
    {
        conn = xqc_conn_server_create(engine, local_addr, local_addrlen,
                                      peer_addr, peer_addrlen, &dcid, &scid,
                                      &default_conn_settings, user_data);
        if (conn == NULL) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|fail to create connection|");
            return -XQC_ECREATE_CONN;
        }
    }

    if (XQC_UNLIKELY(conn == NULL)) {
        if (!xqc_is_reset_packet(&scid, packet_in_buf, packet_in_size,
                                 engine->config->reset_token_key,
                                 engine->config->reset_token_keylen))
        {
            if (xqc_engine_schedule_reset(engine, peer_addr, peer_addrlen, recv_time) != XQC_OK) {
                return -XQC_ECONN_NFOUND;
            }
            xqc_log(engine->log, XQC_LOG_INFO, "|fail to find connection, send reset|size:%uz|scid:%s|",
                    packet_in_size, xqc_scid_str(&scid));
            ret = xqc_engine_send_reset(engine, &scid, peer_addr, peer_addrlen, user_data);
            if (ret) {
                xqc_log(engine->log, XQC_LOG_ERROR, "|fail to send reset|");
            }

        } else {
            /* reset is associated with peer's cid */
            conn = xqc_engine_conns_hash_find(engine, &scid, 'd');
            if (conn) {
                xqc_log(engine->log, XQC_LOG_WARN, "|====>|receive reset, enter draining|size:%uz|scid:%s|",
                        packet_in_size, xqc_scid_str(&scid));
                if (conn->conn_state < XQC_CONN_STATE_DRAINING) {
                    conn->conn_state = XQC_CONN_STATE_DRAINING;
                    xqc_send_ctl_drop_packets(conn->conn_send_ctl);
                    xqc_usec_t pto = xqc_send_ctl_calc_pto(conn->conn_send_ctl);
                    if (!xqc_send_ctl_timer_is_set(conn->conn_send_ctl, XQC_TIMER_DRAINING)) {
                        xqc_send_ctl_timer_set(conn->conn_send_ctl, XQC_TIMER_DRAINING, recv_time, 3 * pto);
                    }
                }
                goto after_process;
            }
            xqc_log(engine->log, XQC_LOG_WARN, "|fail to find connection, exit|size:%uz|scid:%s|",
                    packet_in_size, xqc_scid_str(&scid));
        }
        return -XQC_ECONN_NFOUND;
    }

process:
    xqc_log_event(conn->log, TRA_DATAGRAMS_RECEIVED, packet_in_size);
    xqc_log(engine->log, XQC_LOG_INFO, "|==>|conn:%p|size:%uz|state:%s|recv_time:%ui|",
            conn, packet_in_size, xqc_conn_state_2_str(conn->conn_state), recv_time);

    if (XQC_UNLIKELY(conn->local_addrlen == 0)) {
        xqc_memcpy(conn->local_addr, local_addr, local_addrlen);
        conn->local_addrlen = local_addrlen;
        xqc_log_event(conn->log, CON_CONNECTION_STARTED, conn, XQC_LOG_LOCAL_EVENT);
    }

    /* process packets */
    ret = xqc_conn_process_packet(conn, packet_in_buf, packet_in_size, recv_time);
    if (ret) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|fail to process packets|conn:%p|ret:%d|", conn, ret);
        XQC_CONN_ERR(conn, TRA_FRAME_ENCODING_ERROR);
        goto after_process;
    }

    xqc_send_ctl_timer_set(conn->conn_send_ctl, XQC_TIMER_IDLE,
                           recv_time, xqc_conn_get_idle_timeout(conn) * 1000);

after_process:
    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;

        } else {
            xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_conns_pq_push error|conn:%p|", conn);
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            xqc_conn_destroy(conn);
            return -XQC_EFATAL;
        }
    }

    /* main logic */
    if (++conn->packet_need_process_count >= XQC_MAX_PACKET_PROCESS_BATCH
        || conn->conn_err != 0 || conn->conn_flag & XQC_CONN_FLAG_NEED_RUN)
    {
        xqc_engine_main_logic_internal(engine, conn);
        if (xqc_engine_conns_hash_find(engine, &scid, 's') == NULL) {
            /* to inform upper module when destroy connection in main logic  */
            return  -XQC_ECONN_NFOUND;
        }
    }

    return ret;
}


uint8_t
xqc_engine_config_get_cid_len(xqc_engine_t *engine)
{
    return engine->config->cid_len;
}


xqc_int_t
xqc_engine_add_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len,
    xqc_app_proto_callbacks_t *ap_cbs)
{
    /* register alpn in tls context */
    xqc_int_t ret = xqc_tls_ctx_register_alpn(engine->tls_ctx, alpn, alpn_len);
    if (ret != XQC_OK) {
        return ret;
    }

    xqc_alpn_registration_t *registration = xqc_malloc(sizeof(xqc_alpn_registration_t));
    if (NULL == registration) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|create alpn registration error!");
        return -XQC_EMALLOC;
    }

    registration->alpn = xqc_malloc(alpn_len + 1);
    if (NULL == registration->alpn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|create alpn buffer error!");
        xqc_free(registration);
        return -XQC_EMALLOC;
    }

    xqc_init_list_head(&registration->head);
    xqc_memcpy(registration->alpn, alpn, alpn_len);
    registration->alpn[alpn_len] = '\0';
    registration->alpn_len = alpn_len;
    registration->ap_cbs = *ap_cbs;

    xqc_list_add_tail(&registration->head, &engine->alpn_reg_list);

    xqc_log(engine->log, XQC_LOG_INFO, "|alpn registered|alpn:%s|", alpn);
    return XQC_OK;
}


xqc_int_t
xqc_engine_register_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len,
    xqc_app_proto_callbacks_t *ap_cbs)
{
    xqc_list_head_t *pos, *next;
    xqc_alpn_registration_t *alpn_reg;

    if (NULL == alpn || 0 == alpn_len || alpn_len > XQC_MAX_ALPN_LEN) {
        return -XQC_EPARAM;
    }

    /* check if alpn exists */
    xqc_list_for_each_safe(pos, next, &engine->alpn_reg_list) {
        alpn_reg = xqc_list_entry(pos, xqc_alpn_registration_t, head);
        if (alpn_len == alpn_reg->alpn_len
            && xqc_memcmp(alpn, alpn_reg->alpn, alpn_len) == 0)
        {
            /* if found registration, update */
            alpn_reg->ap_cbs = *ap_cbs;
            return XQC_OK;
        }
    }

    /* not registered, add into alpn_reg_list */
    return xqc_engine_add_alpn(engine, alpn, alpn_len, ap_cbs);
}


xqc_int_t
xqc_engine_unregister_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len)
{
    xqc_list_head_t *pos, *next;
    xqc_alpn_registration_t *alpn_reg;

    xqc_list_for_each_safe(pos, next, &engine->alpn_reg_list) {
        alpn_reg = xqc_list_entry(pos, xqc_alpn_registration_t, head);
        if (alpn_reg && alpn_len == alpn_reg->alpn_len
            && xqc_memcmp(alpn, alpn_reg->alpn, alpn_len) == 0)
        {
            xqc_list_del(&alpn_reg->head);

            /* remove registration */
            if (alpn_reg->alpn) {
                xqc_free(alpn_reg->alpn);
            }

            xqc_free(alpn_reg);

            return xqc_tls_ctx_unregister_alpn(engine->tls_ctx, alpn, alpn_len);
        }
    }

    return -XQC_EALPN_NOT_REGISTERED;
}


xqc_int_t
xqc_engine_get_alpn_callbacks(xqc_engine_t *engine, const char *alpn, size_t alpn_len,
    xqc_app_proto_callbacks_t *cbs)
{
    xqc_list_head_t *pos, *next;
    xqc_alpn_registration_t *alpn_reg;

    if (NULL == alpn || 0 == alpn_len) {
        return -XQC_EPARAM;
    }

    xqc_list_for_each_safe(pos, next, &engine->alpn_reg_list) {
        alpn_reg = xqc_list_entry(pos, xqc_alpn_registration_t, head);
        if (alpn_len == alpn_reg->alpn_len
            && xqc_memcmp(alpn, alpn_reg->alpn, alpn_len) == 0)
        {
            /* if found registration, update */
            *cbs = alpn_reg->ap_cbs;
            return XQC_OK;
        }
    }

    return -XQC_EALPN_NOT_SUPPORTED;
}

void
xqc_engine_free_alpn_list(xqc_engine_t *engine)
{
    /* free alpn registrations */
    xqc_list_head_t *pos, *next;
    xqc_alpn_registration_t *alpn_reg;
    xqc_list_for_each_safe(pos, next, &engine->alpn_reg_list) {
        alpn_reg = xqc_list_entry(pos, xqc_alpn_registration_t, head);

        if (alpn_reg) {
            if (alpn_reg->alpn) {
                xqc_free(alpn_reg->alpn);
            }

            xqc_list_del(&alpn_reg->head);
            xqc_free(alpn_reg);
        }
    }
}

xqc_bool_t
xqc_engine_is_sendmmsg_on(xqc_engine_t *engine)
{
    return engine->config->sendmmsg_on && engine->transport_cbs.write_mmsg;
}
