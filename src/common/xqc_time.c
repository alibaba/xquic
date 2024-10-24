/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_time.h"

#ifdef XQC_SYS_WINDOWS
#ifndef _GETTIMEOFDAY_DEFINED

struct timezone {
    int tz_minuteswest;     /* minutes west of Greenwich */
    int tz_dsttime;         /* type of DST correction */
};

int
gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FILETIME    ft;
    uint64_t    tmpres;
    static int  tzflag;
    if (NULL != tv) {
        GetSystemTimeAsFileTime(&ft);
        tmpres = ((uint64_t) ft.dwHighDateTime << 32)
               | (ft.dwLowDateTime);
        tmpres /= 10; /* Convert from 100-nanosecond intervals to microseconds */
        tmpres -= 11644473600000000ULL; /* Convert from Windows epoch (1601-01-01) to Unix epoch (1970-01-01) */
        tv->tv_sec = tmpres / 1000000;
        tv->tv_usec = tmpres % 1000000;
    }

    if (NULL != tz) {
        if (!tzflag) {
            _tzset();
            tzflag++;
        }
        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
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
