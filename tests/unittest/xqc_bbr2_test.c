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
#define BBR2_TEST_PROBE_BASE_US     2000000
#define BBR2_TEST_PROBE_RAND_US     1000000
#define BBR2_TEST_FC_MIN_ROUNDS     5
#define BBR2_TEST_FC_MAX_ROUNDS     8

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
        CU_ASSERT(wait >= BBR2_TEST_FC_MIN_ROUNDS * 20000);
        CU_ASSERT(wait <= BBR2_TEST_FC_MAX_ROUNDS * 20000);
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
    CU_ASSERT_EQUAL(wait, BBR2_TEST_PROBE_BASE_US);
#endif

    wait = bbr2_test_probe_wait(XQC_BBR2_FLAG_NONE, 20000);
    CU_ASSERT(wait >= BBR2_TEST_PROBE_BASE_US);
    CU_ASSERT(wait < BBR2_TEST_PROBE_BASE_US + BBR2_TEST_PROBE_RAND_US);
#endif
}
