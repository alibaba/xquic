/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_time.h"

#ifdef XQC_SYS_WINDOWS
#ifndef _GETTIMEOFDAY_DEFINED
#define DELTA_EPOCH_IN_TICKS  116444736000000000ULL

int
gettimeofday(struct timeval *tv, void *tzp)
{
    FILETIME    ft;
    uint64_t    tmpres;

    if (NULL != tv) {
        GetSystemTimeAsFileTime(&ft);

        tmpres = ((uint64_t) ft.dwHighDateTime << 32)
               | (ft.dwLowDateTime);

        tmpres -= DELTA_EPOCH_IN_TICKS;
        tv->tv_sec = tmpres / 10000000;
        tv->tv_usec = tmpres % 1000000;
    }

    return 0;
}
#endif
#endif

xqc_usec_t
xqc_now()
{
    /* get microsecond unit time */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    xqc_usec_t ul = tv.tv_sec * (xqc_usec_t)1000000 + tv.tv_usec;
    return  ul;
}

xqc_timestamp_pt xqc_realtime_timestamp  = xqc_now;
xqc_timestamp_pt xqc_monotonic_timestamp = xqc_now;
