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
    xqc_engine_register_alpn(engine, "transport", 9, &transport_cbs);

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
    xqc_engine_register_alpn(engine, "transport", 9, &transport_cbs);

    return engine;
}

const xqc_cid_t *
test_cid_connect(xqc_engine_t *engine)
{
    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(xqc_conn_settings_t));
    conn_settings.proto_version = XQC_IDRAFT_VER_29;
    
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

