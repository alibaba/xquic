
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_ENGINE_H_INCLUDED_
#define _XQC_ENGINE_H_INCLUDED_


#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/tls/xqc_tls.h"
#include "src/common/xqc_list.h"

#define XQC_RESET_CNT_ARRAY_LEN 16384


typedef enum {
    XQC_ENG_FLAG_RUNNING    = 1 << 0,
} xqc_engine_flag_t;


typedef struct xqc_alpn_registration_s {
    xqc_list_head_t             head;

    /* content of application layer protocol */
    char                       *alpn;

    /* length of alpn string */
    size_t                      alpn_len;

    /* Application-Layer-Protocol callback functions */
    xqc_app_proto_callbacks_t   ap_cbs;

} xqc_alpn_registration_t;


typedef struct xqc_engine_s {
    /* for engine itself */
    xqc_engine_type_t               eng_type;
    xqc_engine_callback_t           eng_callback;
    xqc_engine_flag_t               eng_flag;

    /* for connections */
    xqc_config_t                   *config;
    xqc_str_hash_table_t           *conns_hash;             /* scid */
    xqc_str_hash_table_t           *conns_hash_dcid;        /* For reset packet */
    xqc_pq_t                       *conns_active_pq;        /* In process */
    xqc_wakeup_pq_t                *conns_wait_wakeup_pq;   /* Need wakeup after next tick time */
    uint8_t                         reset_sent_cnt[XQC_RESET_CNT_ARRAY_LEN]; /* remote addr hash */
    xqc_usec_t                      reset_sent_cnt_cleared;

    /* tls context */
    xqc_tls_ctx_t                  *tls_ctx;

    /* common */
    xqc_log_t                      *log;
    xqc_random_generator_t         *rand_generator;

    /* for user */
    void                           *user_data;

    /* callback functions for connection transport events */
    xqc_transport_callbacks_t       transport_cbs;

    /* list of xqc_alpn_registration_t */
    xqc_list_head_t                 alpn_reg_list;

} xqc_engine_t;



xqc_usec_t xqc_engine_wakeup_after(xqc_engine_t *engine);


/**
 * Create engine config.
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 */
xqc_config_t *xqc_engine_config_create(xqc_engine_type_t engine_type);

void xqc_engine_config_destroy(xqc_config_t *config);


/**
 * @return > 0 : user should call xqc_engine_main_logic after N ms
 */
xqc_usec_t xqc_engine_wakeup_after(xqc_engine_t *engine);

xqc_connection_t *xqc_engine_conns_hash_find(xqc_engine_t *engine, const xqc_cid_t *cid, char type);

void xqc_engine_process_conn(xqc_connection_t *conn, xqc_usec_t now);

void xqc_engine_main_logic_internal(xqc_engine_t *engine, xqc_connection_t * conn);

xqc_int_t xqc_engine_get_alpn_callbacks(xqc_engine_t *engine, const char *alpn,
    size_t alpn_len, xqc_app_proto_callbacks_t *cbs);

xqc_bool_t xqc_engine_is_sendmmsg_on(xqc_engine_t *engine);

#endif
