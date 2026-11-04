/*
 * BBRv2 PROBE_BW wait, picked when a connection's BBRv2 leaves DRAIN.
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "xquic/xquic.h"
#include "src/congestion_control/xqc_bbr2.h"
#include "src/congestion_control/xqc_sample.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_ctl.h"
#include "xqc_common_test.h"
#include "xqc_bbr2_test.h"

#ifdef XQC_ENABLE_BBR2

/*
 * Mirror the private constants of xqc_bbr2.c: the default wait is
 * xqc_bbr2_bw_probe_base_us plus up to xqc_bbr2_bw_probe_rand_us, and fast
 * convergence waits 1 + xqc_bbr2_fast_convergence_probe_round_base plus up
 * to xqc_bbr2_fast_convergence_probe_round_rand - 1 round trips.
 */
#define XQC_BBR2_TEST_PROBE_BASE_US     2000000
#define XQC_BBR2_TEST_PROBE_RAND_US     1000000
#define XQC_BBR2_TEST_FC_MIN_ROUNDS     5
#define XQC_BBR2_TEST_FC_MAX_ROUNDS     8

static uint32_t bbr2_test_probe_wait(uint32_t cc_flags,
    xqc_usec_t min_rtt_us);

/*
 * Leave DRAIN on one ACK, nothing in flight, of a client connection whose
 * BBRv2 has min_rtt_us as its minimum RTT; return the PROBE_BW wait.
 */
static uint32_t
bbr2_test_probe_wait(uint32_t cc_flags, xqc_usec_t min_rtt_us)
{
    xqc_conn_settings_t    settings;
    xqc_conn_ssl_config_t  ssl_config;
    xqc_engine_t          *engine;
    xqc_connection_t      *conn;
    xqc_send_ctl_t        *ctl;
    xqc_bbr2_t            *bbr2;
    xqc_sample_t           sampler;
    const xqc_cid_t       *cid;
    xqc_usec_t             now;
    uint32_t               wait;

    engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.cong_ctrl_callback = xqc_bbr2_cb;
    settings.cc_params.cc_optimization_flags = cc_flags;

    memset(&ssl_config, 0, sizeof(ssl_config));
    cid = xqc_connect(engine, &settings, NULL, 0, "", 0, &ssl_config,
                      NULL, 0, "transport", NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cid);
    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    ctl = conn->conn_initial_path->path_send_ctl;
    bbr2 = (xqc_bbr2_t *)ctl->ctl_cong;
    now = xqc_monotonic_timestamp();

    bbr2->mode = BBR2_DRAIN;
    bbr2->full_bandwidth_reached = TRUE;
    bbr2->bw_hi[0] = 1250000;
    bbr2->min_rtt = min_rtt_us;
    bbr2->min_rtt_stamp = now;
    bbr2->probe_rtt_min_us = min_rtt_us;
    bbr2->probe_rtt_min_us_stamp = now;

    memset(&sampler, 0, sizeof(sampler));
    sampler.send_ctl = ctl;
    sampler.now = now;
    sampler.rtt = 20000;
    sampler.srtt = 20000;
    xqc_bbr2_cb.xqc_cong_ctl_on_ack_multiple_pkts(bbr2, &sampler);

    CU_ASSERT_EQUAL(bbr2->mode, BBR2_PROBE_BW);
    wait = bbr2->probe_wait_us;
    xqc_engine_destroy(engine);
    return wait;
}

typedef struct bbr2_test_log_s {
    char    line[XQC_MAX_LOG_LEN];
    int     lines;
} bbr2_test_log_t;

/* keep the debug lines of the PROBE_UP checks */
static void
bbr2_test_log_write(xqc_log_level_t lvl, const void *buf, size_t size,
    void *user_data)
{
    bbr2_test_log_t  *capture = user_data;
    char              line[XQC_MAX_LOG_LEN];

    size = xqc_min(size, sizeof(line) - 1);
    memcpy(line, buf, size);
    line[size] = '\0';

    if (strstr(line, "|PROBE_UP_GO|") != NULL) {
        memcpy(capture->line, line, size + 1);
        capture->lines++;
    }
}

/*
 * Give one ACK to the BBRv2 of a client connection in the PROBE_UP phase of
 * PROBE_BW, at its start or, to find a queue, after more than a min_rtt with
 * a large inflight; check the PROBE_UP_GO debug line.
 */
static void
bbr2_test_probe_up_log(xqc_bool_t queuing, const char *expected)
{
    xqc_conn_settings_t    settings;
    xqc_conn_ssl_config_t  ssl_config;
    xqc_engine_t          *engine;
    xqc_connection_t      *conn;
    xqc_send_ctl_t        *ctl;
    xqc_bbr2_t            *bbr2;
    xqc_sample_t           sampler;
    const xqc_cid_t       *cid;
    xqc_usec_t             now;
    xqc_log_callbacks_t   *log_callbacks;
    void                  *log_user_data;
    xqc_log_callbacks_t    callbacks = {0};
    bbr2_test_log_t        capture = {0};

    engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.cong_ctrl_callback = xqc_bbr2_cb;

    memset(&ssl_config, 0, sizeof(ssl_config));
    cid = xqc_connect(engine, &settings, NULL, 0, "", 0, &ssl_config,
                      NULL, 0, "transport", NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cid);
    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    ctl = conn->conn_initial_path->path_send_ctl;
    bbr2 = (xqc_bbr2_t *)ctl->ctl_cong;
    now = xqc_monotonic_timestamp();

    bbr2->mode = BBR2_PROBE_BW;
    bbr2->cycle_idx = BBR2_BW_PROBE_UP;
    bbr2->cycle_start_stamp = queuing ? now - 40000 : now;
    bbr2->full_bandwidth_reached = TRUE;
    bbr2->bw_hi[0] = 1250000;
    bbr2->min_rtt = 20000;
    bbr2->min_rtt_stamp = now;
    bbr2->probe_rtt_min_us = 20000;
    bbr2->probe_rtt_min_us_stamp = now;

    memset(&sampler, 0, sizeof(sampler));
    sampler.send_ctl = ctl;
    sampler.now = now;
    sampler.rtt = 20000;
    sampler.srtt = 20000;
    sampler.prior_inflight = queuing ? 1000000 : 0;

    callbacks.xqc_log_write_err = bbr2_test_log_write;
    log_callbacks = conn->log->log_callbacks;
    log_user_data = conn->log->user_data;
    conn->log->log_level = XQC_LOG_DEBUG;
    conn->log->log_callbacks = &callbacks;
    conn->log->user_data = &capture;

    xqc_bbr2_cb.xqc_cong_ctl_on_ack_multiple_pkts(bbr2, &sampler);

    conn->log->log_callbacks = log_callbacks;
    conn->log->user_data = log_user_data;

#if !defined(XQC_DISABLE_LOG) && !defined(XQC_ONLY_ERROR_LOG)
    CU_ASSERT(capture.lines == 1);
    CU_ASSERT_PTR_NOT_NULL(strstr(capture.line, expected));
#else
    /* the debug line is compiled out */
    CU_ASSERT(capture.lines == 0);
#endif
    CU_ASSERT_EQUAL(bbr2->cycle_idx,
                    queuing ? BBR2_BW_PROBE_DOWN : BBR2_BW_PROBE_UP);
    xqc_engine_destroy(engine);
}

#endif

/*
 * Fast convergence probes again after a few round trips. The wait was
 * computed and dropped, so it stayed 0 and PROBE_BW went back to REFILL
 * on the next ACK.
 */
void
xqc_test_bbr2_probe_wait_fast_convergence(void)
{
#if defined(XQC_ENABLE_BBR2) && XQC_BBR2_PLUS_ENABLED
    for (int i = 0; i < 16; i++) {
        uint32_t wait = bbr2_test_probe_wait(XQC_BBR2_FLAG_FAST_CONVERGENCE,
                                             20000);
        CU_ASSERT(wait >= XQC_BBR2_TEST_FC_MIN_ROUNDS * 20000);
        CU_ASSERT(wait <= XQC_BBR2_TEST_FC_MAX_ROUNDS * 20000);
    }
#endif
}

/*
 * A long min_rtt caps the fast-convergence wait at the default base, and
 * without fast convergence the default wait is kept.
 */
void
xqc_test_bbr2_probe_wait_bounds(void)
{
#ifdef XQC_ENABLE_BBR2
    uint32_t wait;

#if XQC_BBR2_PLUS_ENABLED
    wait = bbr2_test_probe_wait(XQC_BBR2_FLAG_FAST_CONVERGENCE, 600000);
    CU_ASSERT_EQUAL(wait, XQC_BBR2_TEST_PROBE_BASE_US);
#endif

    wait = bbr2_test_probe_wait(XQC_BBR2_FLAG_NONE, 20000);
    CU_ASSERT(wait >= XQC_BBR2_TEST_PROBE_BASE_US);
    CU_ASSERT(wait < XQC_BBR2_TEST_PROBE_BASE_US + XQC_BBR2_TEST_PROBE_RAND_US);
#endif
}

/*
 * The PROBE_UP_GO debug line shows whether a queue was found, and the
 * bandwidth.
 */
void
xqc_test_bbr2_probe_up_log(void)
{
#ifdef XQC_ENABLE_BBR2
    bbr2_test_probe_up_log(XQC_FALSE, "|queuing:0|bw:1250000|");
    bbr2_test_probe_up_log(XQC_TRUE, "|queuing:1|bw:1250000|");
#endif
}
