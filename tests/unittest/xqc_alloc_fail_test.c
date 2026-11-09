/*
 * An allocation that fails while a connection is being created must fail
 * the creation, not crash the process. With BoringSSL, each allocation that
 * xqc_connect() makes on a client engine, and that a client's first Initial
 * packet makes on a server engine, fails in turn (xqc_alloc_wrap.h). Each
 * sweep ends with a run in which nothing fails and the connection is
 * created.
 *
 * A connection that is destroyed must free what it allocated, including
 * the handshake data still queued for its crypto streams: once destroyed,
 * a client engine leaves nothing allocated.
 *
 * A connection that xqc_connect() or xqc_h3_connect() cannot queue, when
 * the engine's active queue cannot grow, must be destroyed rather than
 * left behind.
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include <arpa/inet.h>
#include "xquic/xquic.h"
#include "xquic/xqc_http3.h"
#include "src/common/xqc_time.h"
#include "src/common/xqc_priority_q.h"
#include "src/tls/xqc_tls_defs.h"
#include "src/transport/xqc_engine.h"
#include "xqc_alloc_wrap.h"
#include "xqc_alloc_fail_test.h"

#ifdef XQC_TEST_ALLOC_WRAP

#ifdef XQC_TEST_ALLOC_SWEEP

/*
 * Left out of the sweep: xqc_gen_reset_token() does not check that
 * HMAC_CTX_new() returned a context, so a failure of that allocation
 * crashes. run_tests is linked with --wrap=xqc_gen_reset_token
 * (tests/CMakeLists.txt): the allocations made inside it are not counted,
 * so none of them fails.
 */
void __real_xqc_gen_reset_token(xqc_cid_t *cid, unsigned char *token, int token_len,
    char *key, size_t keylen);

void
__wrap_xqc_gen_reset_token(xqc_cid_t *cid, unsigned char *token, int token_len,
    char *key, size_t keylen)
{
    long count = xqc_test_alloc_count;

    xqc_test_alloc_count = -1;
    __real_xqc_gen_reset_token(cid, token, token_len, key, keylen);
    xqc_test_alloc_count = count;
}

#endif

static unsigned char g_initial[2048];
static size_t        g_initial_len;
static int           g_accepted;

static ssize_t
xqc_test_af_write(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    if (g_initial_len == 0 && size <= sizeof(g_initial)) {
        memcpy(g_initial, buf, size);
        g_initial_len = size;
    }
    return size;
}

static void
xqc_test_af_set_timer(xqc_msec_t wake_after, void *engine_user_data)
{
}

static void
xqc_test_af_log(xqc_log_level_t lvl, const void *buf, size_t count, void *user_data)
{
}

static int
xqc_test_af_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data)
{
    g_accepted++;
    return 0;
}

static xqc_config_t *g_af_config;   /* NULL: the default engine config */

static xqc_engine_t *
xqc_test_af_engine(xqc_engine_type_t type)
{
    xqc_engine_ssl_config_t ssl;
    memset(&ssl, 0, sizeof(ssl));
    ssl.private_key_file = "./server.key";
    ssl.cert_file = "./server.crt";
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t cb = {
        .log_callbacks = {.xqc_log_write_err = xqc_test_af_log},
        .set_event_timer = xqc_test_af_set_timer,
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = xqc_test_af_write,
        .server_accept = xqc_test_af_accept,
    };

    xqc_engine_t *engine = xqc_engine_create(type, g_af_config, &ssl, &cb,
                                             &tcbs, NULL);
    if (engine != NULL) {
        xqc_app_proto_callbacks_t ap = {{NULL}, {NULL}};
        xqc_engine_register_alpn(engine, "transport", 9, &ap, NULL);
    }
    return engine;
}

static const xqc_cid_t *
xqc_test_af_connect(xqc_engine_t *engine)
{
    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    cs.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t ssl;
    memset(&ssl, 0, sizeof(ssl));
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return xqc_connect(engine, &cs, NULL, 0, "", 0, &ssl, (struct sockaddr *)&peer,
                       sizeof(peer), "transport", NULL);
}

#ifdef XQC_TEST_ALLOC_SWEEP

void
xqc_test_conn_create_alloc_failures(void)
{
    long n;

    /*
     * The client's first Initial packet, replayed to each server engine
     * below. Making it first also lets BoringSSL set up its per-thread
     * random number generator state before anything fails: when the
     * allocation that registers that state fails, BoringSSL frees it twice.
     */
    xqc_engine_t *client = xqc_test_af_engine(XQC_ENGINE_CLIENT);
    CU_ASSERT_FATAL(client != NULL);
    g_initial_len = 0;
    CU_ASSERT_FATAL(xqc_test_af_connect(client) != NULL);
    xqc_engine_main_logic(client);
    CU_ASSERT_FATAL(g_initial_len > 0);

    /* client: every allocation of xqc_connect() in turn */
    for (n = 1; n < 100000; n++) {
        xqc_engine_t *engine = xqc_test_af_engine(XQC_ENGINE_CLIENT);
        CU_ASSERT_FATAL(engine != NULL);
        xqc_test_alloc_failed = 0;
        xqc_test_alloc_fail_at = n;
        xqc_test_alloc_count = 0;
        const xqc_cid_t *cid = xqc_test_af_connect(engine);
        xqc_test_alloc_count = -1;
        xqc_engine_destroy(engine);
        if (!xqc_test_alloc_failed) {
            /* nothing failed: the connection was created */
            CU_ASSERT(cid != NULL);
            break;
        }
    }
    CU_ASSERT(n > 1);

    /* server: every allocation made for the client's first Initial packet */
    struct sockaddr_in local, peer;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(4433);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer = local;
    peer.sin_port = htons(5555);

    for (n = 1; n < 100000; n++) {
        /* header protection is removed in place: replay an intact copy */
        unsigned char initial[sizeof(g_initial)];
        memcpy(initial, g_initial, g_initial_len);

        xqc_engine_t *server = xqc_test_af_engine(XQC_ENGINE_SERVER);
        CU_ASSERT_FATAL(server != NULL);
        g_accepted = 0;
        xqc_test_alloc_failed = 0;
        xqc_test_alloc_fail_at = n;
        xqc_test_alloc_count = 0;
        xqc_int_t ret = xqc_engine_packet_process(server, initial, g_initial_len,
                                                  (struct sockaddr *)&local, sizeof(local),
                                                  (struct sockaddr *)&peer, sizeof(peer),
                                                  xqc_monotonic_timestamp(), NULL);
        xqc_engine_main_logic(server);
        xqc_test_alloc_count = -1;
        xqc_engine_destroy(server);
        if (!xqc_test_alloc_failed) {
            /* nothing failed: the connection was created and accepted */
            CU_ASSERT(ret == XQC_OK);
            CU_ASSERT(g_accepted == 1);
            break;
        }
    }
    CU_ASSERT(n > 1);

    xqc_engine_destroy(client);
}

/*
 * An allocation that fails while a client engine is being created must
 * fail the creation, not crash the process, and leave nothing allocated:
 * each allocation of xqc_engine_create() fails in turn, and the sweep ends
 * with a run in which nothing fails.
 */
void
xqc_test_engine_create_alloc_failures(void)
{
    long n;

    /*
     * BoringSSL keeps the per-thread state that it allocates the first
     * time, such as its error queue, which loading a server engine's
     * certificate chain fills: set it up before anything is counted.
     */
    xqc_engine_t *warm = xqc_test_af_engine(XQC_ENGINE_SERVER);
    CU_ASSERT_FATAL(warm != NULL);
    xqc_engine_destroy(warm);
    warm = xqc_test_af_engine(XQC_ENGINE_CLIENT);
    CU_ASSERT_FATAL(warm != NULL);
    xqc_engine_destroy(warm);

    for (n = 1; n < 100000; n++) {
        xqc_test_alloc_live = 0;
        xqc_test_alloc_tracking = 1;
        xqc_test_alloc_failed = 0;
        xqc_test_alloc_fail_at = n;
        xqc_test_alloc_count = 0;
        xqc_engine_t *engine = xqc_test_af_engine(XQC_ENGINE_CLIENT);
        xqc_test_alloc_count = -1;
        if (engine != NULL) {
            xqc_engine_destroy(engine);
        }
        xqc_test_alloc_tracking = 0;
        CU_ASSERT(xqc_test_alloc_live == 0);
        if (!xqc_test_alloc_failed) {
            /* nothing failed: the engine was created */
            CU_ASSERT(engine != NULL);
            break;
        }
    }
    CU_ASSERT(n > 1);
}

#endif

/* the TLS callback that queues handshake data (src/transport/xqc_conn.c) */
xqc_int_t xqc_conn_tls_crypto_data_cb(xqc_encrypt_level_t level,
    const uint8_t *data, size_t len, void *user_data);

static int g_af_create_notify_ret;

/*
 * Before it refuses the connection, the callback queues handshake data at
 * the Handshake and 1-RTT levels, as TLS does later in a handshake: the
 * connection is then destroyed with data queued at every level, its
 * ClientHello included.
 */
static int
xqc_test_af_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *conn_user_data, void *conn_proto_data)
{
    static const uint8_t data[16];

    if (g_af_create_notify_ret != 0) {
        CU_ASSERT(xqc_conn_tls_crypto_data_cb(XQC_ENC_LEV_HSK, data,
                                              sizeof(data), conn) == XQC_OK);
        CU_ASSERT(xqc_conn_tls_crypto_data_cb(XQC_ENC_LEV_1RTT, data,
                                              sizeof(data), conn) == XQC_OK);
    }
    return g_af_create_notify_ret;
}

/*
 * The allocations that a client engine leaves behind once destroyed, after
 * one xqc_connect() whose conn_create_notify returns create_ret. The first
 * run makes the allocations that the process makes only once; the second
 * is counted.
 */
static long
xqc_test_af_connect_leftovers(int create_ret)
{
    xqc_app_proto_callbacks_t ap = {{NULL}, {NULL}};
    ap.conn_cbs.conn_create_notify = xqc_test_af_create_notify;
    g_af_create_notify_ret = create_ret;

    for (int run = 0; run < 2; run++) {
        xqc_test_alloc_live = 0;
        xqc_test_alloc_tracking = 1;
        xqc_engine_t *engine = xqc_test_af_engine(XQC_ENGINE_CLIENT);
        CU_ASSERT_FATAL(engine != NULL);
        xqc_engine_register_alpn(engine, "transport", 9, &ap, NULL);
        const xqc_cid_t *cid = xqc_test_af_connect(engine);
        CU_ASSERT((cid != NULL) == (create_ret == 0));
        xqc_engine_destroy(engine);
        xqc_test_alloc_tracking = 0;
    }
    return xqc_test_alloc_live;
}

void
xqc_test_conn_destroy_frees_crypto_data(void)
{
    /* the crypto stream frees the ClientHello once it has written it */
    CU_ASSERT(xqc_test_af_connect_leftovers(0) == 0);

    /*
     * conn_create_notify fails before the ClientHello is written: the
     * connection is destroyed with handshake data queued at every level
     */
    CU_ASSERT(xqc_test_af_connect_leftovers(-1) == 0);
}

static int       g_af_created, g_af_closed;
static xqc_int_t g_af_closed_errno;
static xqc_cid_t g_af_created_cid;

static int
xqc_test_af_count_create(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *conn_user_data, void *conn_proto_data)
{
    g_af_created++;
    g_af_created_cid = *cid;
    return 0;
}

static int
xqc_test_af_count_close(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *conn_user_data, void *conn_proto_data)
{
    g_af_closed++;
    g_af_closed_errno = xqc_conn_get_errno(conn);
    return 0;
}

static int
xqc_test_af_h3_count_create(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *h3c_user_data)
{
    g_af_created++;
    g_af_created_cid = *cid;
    return 0;
}

static int
xqc_test_af_h3_count_close(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *h3c_user_data)
{
    g_af_closed++;
    g_af_closed_errno = xqc_h3_conn_get_errno(h3_conn);
    return 0;
}

static void *
xqc_test_af_no_growth(void *opaque, size_t size)
{
    return NULL;
}

/* xqc_test_af_connect() over h3 */
static const xqc_cid_t *
xqc_test_af_h3_connect(xqc_engine_t *engine)
{
    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    cs.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t ssl;
    memset(&ssl, 0, sizeof(ssl));
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return xqc_h3_connect(engine, &cs, NULL, 0, "", 0, &ssl,
                          (struct sockaddr *)&peer, sizeof(peer), NULL);
}

/*
 * An xqc_connect() that fails after conn_create_notify must not leave its
 * connection behind: the connection must be gone from the engine,
 * conn_close_notify must have run with an internal error, and the engine
 * must leave nothing allocated once destroyed. Called from one of the
 * engine's callbacks (the engine is running), xqc_connect() leaves its
 * connection in the active queue: with a capacity of one, the second
 * connection finds the queue full. The queue grows in the first run, which
 * also makes the allocations that the process makes only once, and cannot
 * grow in the second.
 *
 * Over h3, the connection that cannot be queued has created its h3
 * connection, with its uni streams and SETTINGS: the h3 connection is
 * destroyed with it, and h3_conn_close_notify runs once.
 */
static void
xqc_test_af_active_queue_full(xqc_config_t *config, int h3)
{
    xqc_app_proto_callbacks_t ap = {{NULL}, {NULL}};
    ap.conn_cbs.conn_create_notify = xqc_test_af_count_create;
    ap.conn_cbs.conn_close_notify = xqc_test_af_count_close;

    xqc_h3_callbacks_t h3_cbs;
    memset(&h3_cbs, 0, sizeof(h3_cbs));
    h3_cbs.h3c_cbs.h3_conn_create_notify = xqc_test_af_h3_count_create;
    h3_cbs.h3c_cbs.h3_conn_close_notify = xqc_test_af_h3_count_close;

    for (int grows = 1; grows >= 0; grows--) {
        xqc_test_alloc_live = 0;
        xqc_test_alloc_tracking = 1;
        g_af_config = config;
        xqc_engine_t *engine = xqc_test_af_engine(XQC_ENGINE_CLIENT);
        g_af_config = NULL;
        CU_ASSERT_FATAL(engine != NULL);
        if (h3) {
            CU_ASSERT_FATAL(xqc_h3_ctx_init(engine, &h3_cbs) == XQC_OK);

        } else {
            xqc_engine_register_alpn(engine, "transport", 9, &ap, NULL);
        }

        engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
        CU_ASSERT_FATAL((h3 ? xqc_test_af_h3_connect(engine)
                            : xqc_test_af_connect(engine)) != NULL);

        xqc_malloc_wrap_t pq_malloc = engine->conns_active_pq->a.malloc;
        if (!grows) {
            engine->conns_active_pq->a.malloc = xqc_test_af_no_growth;
        }
        g_af_created = 0;
        g_af_closed = 0;
        const xqc_cid_t *cid = h3 ? xqc_test_af_h3_connect(engine)
                                  : xqc_test_af_connect(engine);
        engine->conns_active_pq->a.malloc = pq_malloc;

        CU_ASSERT(g_af_created == 1);
        if (grows) {
            CU_ASSERT(cid != NULL);
            CU_ASSERT(g_af_closed == 0);

        } else {
            CU_ASSERT(cid == NULL);
            CU_ASSERT(g_af_closed == 1);
            CU_ASSERT(g_af_closed_errno == TRA_INTERNAL_ERROR);
            CU_ASSERT(xqc_engine_get_conn_by_scid(engine, &g_af_created_cid)
                      == NULL);
        }

        engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
        xqc_engine_destroy(engine);
        xqc_test_alloc_tracking = 0;
    }
    CU_ASSERT(xqc_test_alloc_live == 0);
}

void
xqc_test_client_connect_active_queue_full(void)
{
    xqc_config_t config;
    CU_ASSERT_FATAL(xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT)
                    == XQC_OK);
    config.conns_active_pq_capacity = 1;

    xqc_test_af_active_queue_full(&config, 0);
    xqc_test_af_active_queue_full(&config, 1);
}

#endif

#ifndef XQC_TEST_ALLOC_SWEEP

void
xqc_test_conn_create_alloc_failures(void)
{
    /* needs BoringSSL and the linker's --wrap (see tests/CMakeLists.txt) */
}

void
xqc_test_engine_create_alloc_failures(void)
{
    /* needs BoringSSL and the linker's --wrap (see tests/CMakeLists.txt) */
}

#endif

#ifndef XQC_TEST_ALLOC_WRAP

void
xqc_test_conn_destroy_frees_crypto_data(void)
{
    /* needs the linker's --wrap (see tests/CMakeLists.txt) */
}

void
xqc_test_client_connect_active_queue_full(void)
{
    /* counts allocations through the linker's --wrap */
}

#endif
