/*
 * Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * Implements Kathleen Nichols' algorithm for tracking the minimum (or maximum)
 * estimate of a stream of samples over some fixed time interval
 */

#ifndef _XQC_WIN_FILTER_H_INCLUDED_
#define _XQC_WIN_FILTER_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

struct xqc_win_sample {
    uint64_t t;
    uint64_t val;
};

typedef struct {
    struct xqc_win_sample s[3];
} xqc_win_filter_t;

static uint64_t
xqc_win_filter_get(const xqc_win_filter_t *w)
{
    return w->s[0].val;
}

static uint64_t
xqc_win_filter_reset(xqc_win_filter_t *w, uint64_t t, uint64_t nval)
{
    struct xqc_win_sample nsample = {.t = t, .val = nval };
    w->s[0] = w->s[1] = w->s[2] = nsample;
    return w->s[0].val;
}

uint64_t xqc_win_filter_max(xqc_win_filter_t *w,
                                uint64_t win,
                                uint64_t t,
                                uint64_t nval);

uint64_t xqc_win_filter_min(xqc_win_filter_t *w,
                                uint64_t win,
                                uint64_t t,
                                uint64_t nval);

#endif