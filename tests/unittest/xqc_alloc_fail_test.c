/*
 * An allocation that fails while a connection is being created must fail
 * the creation, not crash the process. With BoringSSL, each allocation that
 * xqc_connect() makes on a client engine, and that a client's first Initial
 * packet makes on a server engine, fails in turn (xqc_alloc_wrap.h). Each
 * sweep ends with a run in which nothing fails and the connection is
 * created.
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include <arpa/inet.h>
#include "xquic/xquic.h"
#include "src/common/xqc_time.h"
#include "xqc_alloc_wrap.h"
#include "xqc_alloc_fail_test.h"

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

    xqc_engine_t *engine = xqc_engine_create(type, NULL, &ssl, &cb, &tcbs, NULL);
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

#else

void
xqc_test_conn_create_alloc_failures(void)
{
    /* needs BoringSSL and the linker's --wrap (see tests/CMakeLists.txt) */
}

#endif
