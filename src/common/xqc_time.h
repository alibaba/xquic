/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_TIME_H_INCLUDED_
#define _XQC_TIME_H_INCLUDED_

#include <time.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>

#if !defined(XQC_SYS_WINDOWS) || defined(XQC_ON_MINGW)
#include <sys/time.h>
#endif

#ifdef XQC_SYS_WINDOWS
#ifndef _GETTIMEOFDAY_DEFINED
int gettimeofday(struct timeval *tv, struct timezone *tz);
#endif
#endif


/**
 * @brief get realtime timestamp
 */
extern xqc_timestamp_pt xqc_realtime_timestamp;

/**
 * @brief get monotonic increasing timestamp
 */
extern xqc_timestamp_pt xqc_monotonic_timestamp;

#endif /* _XQC_TIME_H_INCLUDED_ */

