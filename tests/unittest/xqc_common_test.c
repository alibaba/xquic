/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "xqc_common_test.h"
#include "src/common/xqc_object_manager.h"
#include "src/common/xqc_rbtree.h"
#include "src/common/xqc_fifo.h"
#include "src/common/xqc_log_event_callback.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/congestion_control/xqc_bbr_common.h"


typedef struct person_s {
    int age;
    char name[20];
    xqc_queue_t queue;
} person_t;

typedef struct xqc_item_s {
    xqc_object_id_t object_id;
    xqc_list_head_t list;
    int data;
} xqc_item_t;

typedef struct xqc_test_log_capture_s {
    unsigned char   buf[XQC_MAX_LOG_LEN];
    size_t          size;
} xqc_test_log_capture_t;

static void
xqc_test_qlog_write(qlog_event_importance_t imp, const void *buf, size_t size,
    void *user_data)
{
    xqc_test_log_capture_t  *capture = user_data;
    size_t                   copy_size;

    (void) imp;
    copy_size = xqc_min(size, sizeof(capture->buf) - 1);
    memcpy(capture->buf, buf, copy_size);
    capture->buf[copy_size] = '\0';
    capture->size = copy_size;
}

/*
 * A congestion controller for the REC_METRICS_UPDATED event, whose 64-bit
 * values do not fit in 32 bits, so that a 32-bit conversion shows.
 */
static uint64_t
xqc_test_metrics_cwnd(void *cong)
{
    return 0x100000001ULL;
}

static void
xqc_test_metrics_init_bbr(void *cong, xqc_sample_t *sampler,
    xqc_cc_params_t cc_params)
{
}

static uint32_t
xqc_test_metrics_pacing_rate(void *cong)
{
    return 3000000;
}

static uint32_t
xqc_test_metrics_bandwidth(void *cong)
{
    return 2000000;
}

static uint8_t
xqc_test_metrics_mode(void *cong)
{
    return 2;
}

static uint64_t
xqc_test_metrics_min_rtt(void *cong)
{
    return 0x100000006ULL;
}

static void
xqc_test_metrics_updated_log(const xqc_cong_ctrl_callback_t *cc,
    const char *expected)
{
    xqc_test_log_capture_t  capture = {0};
    xqc_log_callbacks_t     callbacks = {0};
    xqc_log_t               log = {0};
    xqc_send_ctl_t          send_ctl = {0};

    callbacks.xqc_qlog_event_write = xqc_test_qlog_write;
    log.log_event = 1;
    log.qlog_importance = EVENT_IMPORTANCE_EXTRA;
    log.log_callbacks = &callbacks;
    log.user_data = &capture;

    send_ctl.ctl_cong_callback = cc;
    send_ctl.ctl_bytes_in_flight = 1200;
    send_ctl.ctl_app_limited = 0x100000002ULL;
    send_ctl.ctl_srtt = 0x100000003ULL;
    send_ctl.ctl_latest_rtt = 0x100000004ULL;
    send_ctl.ctl_rttvar = 0x100000005ULL;
    send_ctl.ctl_pto_count = 7;
    send_ctl.ctl_send_count = 8;
    send_ctl.ctl_lost_count = 9;
    send_ctl.ctl_tlp_count = 10;
    send_ctl.ctl_recv_count = 11;

    xqc_log_REC_METRICS_UPDATED_callback(&log, "xqc_test", &send_ctl);

    CU_ASSERT(capture.size > 0);
    CU_ASSERT_STRING_EQUAL(capture.buf, expected);
}

void
xqc_test_metrics_updated_log_bbr(void)
{
    xqc_bbr_info_interface_t  info = {0};
    xqc_cong_ctrl_callback_t  cc = {0};

    info.mode = xqc_test_metrics_mode;
    info.min_rtt = xqc_test_metrics_min_rtt;
    cc.xqc_cong_ctl_get_cwnd = xqc_test_metrics_cwnd;
    cc.xqc_cong_ctl_init_bbr = xqc_test_metrics_init_bbr;
    cc.xqc_cong_ctl_get_pacing_rate = xqc_test_metrics_pacing_rate;
    cc.xqc_cong_ctl_get_bandwidth_estimate = xqc_test_metrics_bandwidth;
    cc.xqc_cong_ctl_info_cb = &info;

    xqc_test_metrics_updated_log(&cc,
        "|xqc_test|cwnd:4294967297|inflight:1200|mode:2|applimit:4294967298|"
        "pacing_rate:3000000|bw:2000000|srtt:4294967299|"
        "latest_rtt:4294967300|ctl_rttvar:4294967301|pto_count:7|"
        "min_rtt:4294967302|send:8|lost:9|tlp:10|recv:11|");
}

void
xqc_test_metrics_updated_log_no_bbr(void)
{
    xqc_cong_ctrl_callback_t  cc = {0};

    cc.xqc_cong_ctl_get_cwnd = xqc_test_metrics_cwnd;

    xqc_test_metrics_updated_log(&cc,
        "|xqc_test|cwnd:4294967297|inflight:1200|applimit:4294967298|"
        "srtt:4294967299|latest_rtt:4294967300|pto_count:7|send:8|lost:9|"
        "tlp:10|recv:11|");
}

static void
xqc_test_connection_closed_log(xqc_connection_t *conn, const char *expected)
{
    xqc_test_log_capture_t  capture = {0};
    xqc_log_callbacks_t     callbacks = {0};
    xqc_log_t               log = {0};

    callbacks.xqc_qlog_event_write = xqc_test_qlog_write;
    log.log_event = 1;
    log.qlog_importance = EVENT_IMPORTANCE_BASE;
    log.log_callbacks = &callbacks;
    log.user_data = &capture;

    xqc_log_CON_CONNECTION_CLOSED_callback(&log, "xqc_test", conn);

    CU_ASSERT(capture.size > 0);
    CU_ASSERT_STRING_EQUAL(capture.buf, expected);
}

void
xqc_test_connection_closed_log_no_error(void)
{
    xqc_connection_t  conn = {0};

    conn.MTU_updated_count = 0xffffffffu;
    conn.packet_dropped_count = 0xffffffffffffffffULL;

    xqc_test_connection_closed_log(
        &conn,
        "|xqc_test|err_code:0|mtu_updatad_count:4294967295|"
        "pkt_dropped:18446744073709551615|");
}

void
xqc_test_connection_closed_log_with_error(void)
{
    xqc_connection_t  conn = {0};
    xqc_path_ctx_t     path = {0};
    xqc_send_ctl_t     send_ctl = {0};

    xqc_init_list_head(&conn.conn_paths_list);
    xqc_init_list_head(&conn.conn_closed_paths_list);
    path.path_id = 7;
    path.path_send_ctl = &send_ctl;
    xqc_list_add_tail(&path.path_list, &conn.conn_paths_list);

    conn.conn_err = 0x100000002ULL;
    conn.MTU_updated_count = 0xffffffffu;
    conn.packet_dropped_count = 0x100000004ULL;

    xqc_test_connection_closed_log(
        &conn,
        "|xqc_test|err_code:4294967298|mtu_updatad_count:4294967295|"
        "pkt_dropped:4294967300|recent_congestion:<path:7, (0,0,0)>|");
}

/*
 * Fill the stack below the caller with non-zero bytes, so that a formatter
 * called next finds them, not a zero left there by chance, if it reads its
 * buffer past what it wrote.
 */
static void xqc_test_dirty_stack(void) __attribute__((noinline));

static void
xqc_test_dirty_stack(void)
{
    volatile unsigned char  stack[XQC_MAX_LOG_LEN * 4];
    size_t                  i;

    for (i = 0; i < sizeof(stack); i++) {
        stack[i] = 'X';
    }
}

static void
xqc_test_alpn_information_log(xqc_test_log_capture_t *capture,
    const unsigned char *client_alpn, unsigned int client_alpn_len)
{
    static const unsigned char  server_alpn[] = "\x09" "transport" "\x02" "h3";

    xqc_log_callbacks_t  callbacks = {0};
    xqc_log_t            log = {0};

    callbacks.xqc_qlog_event_write = xqc_test_qlog_write;
    log.log_event = 1;
    log.qlog_importance = EVENT_IMPORTANCE_CORE;
    log.log_callbacks = &callbacks;
    log.user_data = capture;

    xqc_test_dirty_stack();
    xqc_log_TRA_ALPN_INFORMATION_callback(&log, "xqc_test", server_alpn,
                                          sizeof(server_alpn) - 1,
                                          client_alpn, client_alpn_len,
                                          "h3", 2);
}

void
xqc_test_alpn_information_log_negotiated(void)
{
    static const unsigned char  client_alpn[] = "\x02" "h3" "\x05" "h3-29";

    xqc_test_log_capture_t  capture = {0};

    xqc_test_alpn_information_log(&capture, client_alpn,
                                  sizeof(client_alpn) - 1);

    CU_ASSERT_STRING_EQUAL(capture.buf,
                           "|xqc_test|client_alpn:h3 h3-29 "
                           "|server_alpn:transport h3 |selected_alpn:h3|");
}

void
xqc_test_alpn_information_log_truncated(void)
{
    static const char  prefix[] = "|xqc_test|client_alpn:";

    unsigned char           client_alpn[9 * 256];
    xqc_test_log_capture_t  capture = {0};
    size_t                  i, n;

    /* nine protocol names of 255 bytes: more than a log line holds */
    for (i = 0; i < 9; i++) {
        client_alpn[i * 256] = 255;
        memset(&client_alpn[i * 256 + 1], 'a' + i, 255);
    }

    xqc_test_alpn_information_log(&capture, client_alpn, sizeof(client_alpn));

    /* the line is the client list, cut at the log line limit */
    CU_ASSERT(capture.size == sizeof(capture.buf) - 1);
    CU_ASSERT(memcmp(capture.buf, prefix, sizeof(prefix) - 1) == 0);
    for (i = sizeof(prefix) - 1; i < capture.size; i++) {
        n = i - (sizeof(prefix) - 1);
        if (capture.buf[i] != (n % 256 == 255 ? ' ' : 'a' + n / 256)) {
            break;
        }
    }
    CU_ASSERT(i == capture.size);
}

static inline void
test_object_manager_cb(xqc_object_t *o)
{
    /*xqc_item_t* item = (xqc_item_t*)o;
    printf("id:%u, data:%d\n", item->object_id, item->data);*/
}

int
test_object_manager()
{
    xqc_object_manager_t *manager = xqc_object_manager_create(sizeof(xqc_item_t), 4, xqc_default_allocator);
    if (manager == NULL) {
        return 1;
    }

    xqc_item_t *item1 = (xqc_item_t*)xqc_object_manager_alloc(manager);
    if (item1) {
        item1->data = 1;
    }

    xqc_item_t *item2 = (xqc_item_t*)xqc_object_manager_alloc(manager);
    if (item2) {
        item2->data = 2;
        xqc_object_manager_free(manager, item2->object_id);
    }

    xqc_item_t *item3 = (xqc_item_t*)xqc_object_manager_alloc(manager);
    if (item3) {
        item3->data = 3;
    }

    xqc_object_manager_foreach(manager, test_object_manager_cb);

    CU_ASSERT(xqc_object_manager_used_count(manager) == 2);
    CU_ASSERT(xqc_object_manager_free_count(manager) == 2);

    xqc_object_manager_destroy(manager);

    return 0;
}

static inline void
rbtree_cb(xqc_rbtree_node_t* node)
{
    //printf("key=%lu\n", (unsigned long)node->key);
}

int
test_rbtree()
{
    xqc_rbtree_t rbtree;
    xqc_rbtree_init(&rbtree);

    xqc_rbtree_node_t list[] = {
        { 0, 0, 0, 5, xqc_rbtree_black },
        { 0, 0, 0, 1, xqc_rbtree_black },
        { 0, 0, 0, 4, xqc_rbtree_black },
        { 0, 0, 0, 7, xqc_rbtree_black },
        { 0, 0, 0, 8, xqc_rbtree_black },
        { 0, 0, 0, 9, xqc_rbtree_black },
        { 0, 0, 0, 2, xqc_rbtree_black },
        { 0, 0, 0, 0, xqc_rbtree_black },
        { 0, 0, 0, 3, xqc_rbtree_black },
        { 0, 0, 0, 6, xqc_rbtree_black },
    };

    for (size_t i = 0; i < sizeof(list)/sizeof(*list); ++i) {
        xqc_rbtree_insert(&rbtree, &list[i]);
    }

    xqc_rbtree_insert(&rbtree, &list[1]);

    xqc_rbtree_node_t* p = xqc_rbtree_find(&rbtree, 6);
    if (p) {
        //printf("found 6\n");
    }

    p = xqc_rbtree_find(&rbtree, 16);
    if (!p) {
        //printf("not found 16\n");
    }

    xqc_rbtree_delete(&rbtree, 7);
    xqc_rbtree_delete(&rbtree, 1);
    xqc_rbtree_delete(&rbtree, 9);

    CU_ASSERT(xqc_rbtree_count(&rbtree) == 7);

    xqc_rbtree_foreach(&rbtree, rbtree_cb);
    return 0;
}

void
xqc_test_common()
{
    /* test queue */
    xqc_queue_t q;
    xqc_queue_init(&q);
    person_t p1 = { 1, "a1", xqc_queue_initialize(p1.queue) };
    person_t p2 = { 2, "z2", xqc_queue_initialize(p2.queue) };
    person_t p3 = { 3, "s3", xqc_queue_initialize(p3.queue) };
    person_t p4 = { 4, "f4", xqc_queue_initialize(p4.queue) };

    xqc_queue_insert_head(&q, &p1.queue);
    xqc_queue_insert_tail(&q, &p2.queue);
    xqc_queue_insert_head(&q, &p3.queue);
    xqc_queue_insert_tail(&q, &p4.queue);
    xqc_queue_remove(&p3.queue);

    int a[4] = {1,2,4};
    int i = 0;

    xqc_queue_t *pos;
    xqc_queue_foreach(pos, &q) {
        person_t* p = xqc_queue_data(pos, person_t, queue);
        CU_ASSERT(p->age == a[i]);
        ++i;
    }

    /* test hash functions */
    xqc_md5_t ctx;
    xqc_md5_init(&ctx);
    unsigned char buf[] = "hello,world";
    xqc_md5_update(&ctx, buf, 11);

    unsigned char final[16] = {};
    xqc_md5_final(final, &ctx);

    uint32_t hash_value = xqc_murmur_hash2(buf, 11);

    test_object_manager();

    test_rbtree();

    /* test fifo */
    xqc_fifo_t fifo;
    memset(&fifo, 0, sizeof(fifo));
    xqc_fifo_init(&fifo, xqc_default_allocator, sizeof(int), 4);

    xqc_fifo_push_int(&fifo, 3);
    xqc_fifo_push_int(&fifo, 1);
    xqc_fifo_push_int(&fifo, 2);
    xqc_fifo_push_int(&fifo, 4);

    xqc_fifo_pop(&fifo);
    xqc_fifo_pop(&fifo);
    xqc_fifo_push_int(&fifo, 9);
    xqc_fifo_push_int(&fifo, 7);
    xqc_fifo_pop(&fifo);
    xqc_fifo_push_int(&fifo, 5);

    CU_ASSERT(xqc_fifo_length(&fifo) == 4);

    while (xqc_fifo_empty(&fifo) != XQC_TRUE) {
        int i = xqc_fifo_top_int(&fifo);
        //printf("%d, length:%d\n", i, xqc_fifo_length(&fifo));
        xqc_fifo_pop(&fifo);
    }

    xqc_fifo_release(&fifo);
}


#define def_engine_ssl_config   \
xqc_engine_ssl_config_t  engine_ssl_config;             \
engine_ssl_config.private_key_file = "./server.key";    \
engine_ssl_config.cert_file = "./server.crt";           \
engine_ssl_config.ciphers = XQC_TLS_CIPHERS;            \
engine_ssl_config.groups = XQC_TLS_GROUPS;              \
engine_ssl_config.session_ticket_key_len = 0;           \
engine_ssl_config.session_ticket_key_data = NULL;

static ssize_t
null_socket_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    return size;
}

static ssize_t
null_socket_write_ex(uint64_t path_id,
    const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    return size;
}

static void
null_set_event_timer(xqc_msec_t wake_after, void *engine_user_data)
{
    return;
}

void
xqc_write_log_default(xqc_log_level_t lvl, const void *buf, size_t count, void *user_data)
{
    return;
}

const xqc_log_callbacks_t xqc_null_log_cb = {
    .xqc_log_write_err = xqc_write_log_default,
};

xqc_engine_t *
test_create_engine()
{
    def_engine_ssl_config;
    xqc_engine_callback_t callback = {
        .log_callbacks = xqc_null_log_cb,
        .set_event_timer = null_set_event_timer,
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = null_socket_write,
        .write_socket_ex = null_socket_write_ex,
    };

    xqc_conn_settings_t conn_settings;
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT, NULL, &engine_ssl_config,
                                             &callback, &tcbs, NULL);

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = NULL,
            .h3_conn_close_notify = NULL,
            .h3_conn_handshake_finished = NULL,
        },
        .h3r_cbs = {
            .h3_request_create_notify = NULL,
            .h3_request_close_notify = NULL,
            .h3_request_read_notify = NULL,
            .h3_request_write_notify = NULL,
        }
    };

    /* init http3 context */
    int ret = xqc_h3_ctx_init(engine, &h3_cbs);
    if (ret != XQC_OK) {
        xqc_engine_destroy(engine);
        return NULL;
    }

    /* transport ALPN */
    xqc_app_proto_callbacks_t transport_cbs = {{NULL}, {NULL}};
    xqc_engine_register_alpn(engine, "transport", 9, &transport_cbs, NULL);

    return engine;
}

xqc_engine_t *
test_create_engine_server()
{
    def_engine_ssl_config;
    xqc_engine_callback_t callback = {
        .log_callbacks = xqc_null_log_cb,
        .set_event_timer = null_set_event_timer,
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = null_socket_write,
    };

    xqc_conn_settings_t conn_settings;
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_SERVER, NULL, &engine_ssl_config,
                                             &callback, &tcbs, NULL);

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = NULL,
            .h3_conn_close_notify = NULL,
            .h3_conn_handshake_finished = NULL,
        },
        .h3r_cbs = {
            .h3_request_create_notify = NULL,
            .h3_request_close_notify = NULL,
            .h3_request_read_notify = NULL,
            .h3_request_write_notify = NULL,
        }
    };

    /* init http3 context */
    int ret = xqc_h3_ctx_init(engine, &h3_cbs);
    if (ret != XQC_OK) {
        xqc_engine_destroy(engine);
        return NULL;
    }

    /* transport ALPN */
    xqc_app_proto_callbacks_t transport_cbs = {{NULL}, {NULL}};
    xqc_engine_register_alpn(engine, "transport", 9, &transport_cbs, NULL);

    return engine;
}

const xqc_cid_t *
test_cid_connect(xqc_engine_t *engine)
{
    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(xqc_conn_settings_t));
    conn_settings.proto_version = XQC_VERSION_V1;
    
    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    const xqc_cid_t *cid = xqc_connect(engine, &conn_settings, NULL, 0, "", 0, &conn_ssl_config,
                                       NULL, 0, "transport", NULL);
    return cid;
}

static xqc_connection_t *
test_connect(xqc_engine_t *engine)
{
    const xqc_cid_t *cid = test_cid_connect(engine);
    if (cid == NULL) {
        return NULL;
    }
    return xqc_engine_conns_hash_find(engine, cid, 's');
}

xqc_connection_t *
test_engine_connect()
{
    xqc_engine_t *engine = test_create_engine();
    if (engine == NULL) {
        return NULL;
    }
    xqc_connection_t *conn = test_connect(engine);
    return conn;
}

void
xqc_test_murmur_hash2(void)
{
    unsigned char  text[] = "hello,world";

    CU_ASSERT_EQUAL(xqc_murmur_hash2(text, 11), 0xb28179afU);
}

/*
 * A byte of 0x80 or more in the top position of a 4-byte block must not be
 * shifted into the sign bit of an int, which is undefined behaviour.
 */
void
xqc_test_murmur_hash2_high_bytes(void)
{
    unsigned char  all[4] = {0xff, 0xff, 0xff, 0xff};
    unsigned char  high[4] = {0x00, 0x00, 0x00, 0x80};

    CU_ASSERT_EQUAL(xqc_murmur_hash2(all, 4), 0x14acb3daU);
    CU_ASSERT_EQUAL(xqc_murmur_hash2(high, 4), 0x26de7447U);
}
