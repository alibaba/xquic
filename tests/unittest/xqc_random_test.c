/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>
#include "src/common/xqc_random.h"
#include "src/common/xqc_common.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_packet_parser.h"
#include "xqc_common_test.h"

void
xqc_test_get_random()
{
    u_char buf[1024];
    xqc_random_generator_t *rand_gen = NULL;
    xqc_log_t log;

    rand_gen = xqc_random_generator_create(&log);
    CU_ASSERT(rand_gen != NULL);

    int ret = xqc_get_random(rand_gen, buf, 1024);

    CU_ASSERT(ret == XQC_OK);
    xqc_random_generator_destroy(rand_gen);
}


#ifndef XQC_COMPAT_GENERATE_SR_PKT
/*
 * Make rand_gen read its next bytes from a source at its end: its buffer
 * is used up, and its descriptor is a pipe without writer.
 */
static void
xqc_test_random_source_ends(xqc_random_generator_t *rand_gen)
{
    int fds[2];

    CU_ASSERT_FATAL(pipe(fds) == 0);
    close(fds[1]);

    if (rand_gen->rand_fd != -1) {
        close(rand_gen->rand_fd);
    }
    rand_gen->rand_fd = fds[0];
    rand_gen->rand_buf_offset = rand_gen->rand_buf.len;
}
#endif


/*
 * RFC 9000 Section 10.3: the bits of a stateless reset before its token are
 * unpredictable. Without random bytes, no stateless reset is made.
 */
void
xqc_test_reset_packet_random_error()
{
#ifndef XQC_COMPAT_GENERATE_SR_PKT
    unsigned char buf[XQC_STATELESS_RESET_PKT_MAX_LEN];
    char key[] = "test reset key";
    xqc_cid_t cid;

    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    xqc_cid_set(&cid, (const unsigned char *) "\x01\x02\x03\x04", 4);

    CU_ASSERT_EQUAL(xqc_gen_reset_packet(&cid, buf, key, sizeof(key) - 1,
                                         sizeof(buf), engine->rand_generator),
                    sizeof(buf));

    xqc_test_random_source_ends(engine->rand_generator);
    CU_ASSERT(xqc_gen_reset_packet(&cid, buf, key, sizeof(key) - 1,
                                   sizeof(buf), engine->rand_generator) < 0);

    xqc_engine_destroy(engine);
#endif
}


static ssize_t
xqc_test_random_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data)
{
    return size;
}

static void
xqc_test_random_set_event_timer(xqc_msec_t wake_after, void *engine_user_data)
{
}

/*
 * The connection hash tables of an engine are keyed with random bytes.
 * Without them, the engine is not created. No descriptor is free under the
 * file limit, so /dev/urandom cannot be opened.
 */
void
xqc_test_engine_create_random_error()
{
    xqc_engine_ssl_config_t ssl_config;
    xqc_engine_callback_t callback = {
        .log_callbacks = xqc_null_log_cb,
        .set_event_timer = xqc_test_random_set_event_timer,
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = xqc_test_random_write_socket,
    };
    struct rlimit saved, limit;
    xqc_engine_t *engine;
    int fd;

    memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.ciphers = XQC_TLS_CIPHERS;
    ssl_config.groups = XQC_TLS_GROUPS;

    /* the lowest free descriptor */
    fd = open("/dev/null", O_RDONLY);
    CU_ASSERT_FATAL(fd >= 0);
    close(fd);
    CU_ASSERT_FATAL(getrlimit(RLIMIT_NOFILE, &saved) == 0);
    limit = saved;
    limit.rlim_cur = fd;

    CU_ASSERT_FATAL(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    engine = xqc_engine_create(XQC_ENGINE_CLIENT, NULL, &ssl_config,
                               &callback, &tcbs, NULL);
    CU_ASSERT(setrlimit(RLIMIT_NOFILE, &saved) == 0);

    CU_ASSERT_PTR_NULL(engine);
    if (engine != NULL) {
        xqc_engine_destroy(engine);
    }
}
