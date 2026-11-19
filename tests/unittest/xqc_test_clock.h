/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_TEST_CLOCK_H
#define XQC_TEST_CLOCK_H

#include "src/common/xqc_time.h"

/*
 * The virtual clock of the unit tests. A test that depends on the time runs
 * on it, so that its result depends neither on when, how fast or how often
 * it runs, nor on the host clock being stepped: the time is what the test
 * makes it. The library reads it through both of its clocks, which every
 * timestamp of an engine and of its connections comes from.
 *
 * xqc_test_clock_start() comes before the engine is created, so that all
 * of its timestamps are on this clock, and xqc_test_clock_stop() after the
 * engine is destroyed, which gives the host clocks back. A test that ends
 * early on a fatal assertion leaves the clock installed: the next start
 * keeps the host clocks that the first one saved.
 */

/* a date in 2023, in microseconds since the epoch: its count of seconds fits
 * in 32 bits, as the expiry times of tokens need */
#define XQC_TEST_CLOCK_EPOCH    ((xqc_usec_t) 1700000000 * 1000000)

typedef struct xqc_test_clock_s {
    xqc_usec_t now;
    xqc_timestamp_pt host_realtime;
    xqc_timestamp_pt host_monotonic;
    int started;
} xqc_test_clock_t;

/* one clock for all the test files: the definitions of the weak symbol
 * of each of them are one object */
extern xqc_test_clock_t xqc_test_clock_state;
__attribute__((weak)) xqc_test_clock_t xqc_test_clock_state;


static inline xqc_usec_t
xqc_test_clock_now(void)
{
    return xqc_test_clock_state.now;
}


static inline void
xqc_test_clock_set(xqc_usec_t now)
{
    xqc_test_clock_state.now = now;
}


static inline void
xqc_test_clock_advance(xqc_usec_t us)
{
    xqc_test_clock_state.now += us;
}


static inline void
xqc_test_clock_start(void)
{
    if (!xqc_test_clock_state.started) {
        xqc_test_clock_state.host_realtime = xqc_realtime_timestamp;
        xqc_test_clock_state.host_monotonic = xqc_monotonic_timestamp;
        xqc_test_clock_state.started = 1;
    }

    xqc_test_clock_state.now = XQC_TEST_CLOCK_EPOCH;
    xqc_realtime_timestamp = xqc_test_clock_now;
    xqc_monotonic_timestamp = xqc_test_clock_now;
}


static inline void
xqc_test_clock_stop(void)
{
    if (xqc_test_clock_state.started) {
        xqc_realtime_timestamp = xqc_test_clock_state.host_realtime;
        xqc_monotonic_timestamp = xqc_test_clock_state.host_monotonic;
        xqc_test_clock_state.started = 0;
    }
}

#endif /* XQC_TEST_CLOCK_H */
