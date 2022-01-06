/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_TIME_H_INCLUDED_
#define _XQC_TIME_H_INCLUDED_

#ifndef WIN32
#include <sys/time.h>
#endif
#ifdef MINGW_HAS_SECURE_API
#include <sec_api/time_s.h>
#endif
#include <time.h>
#include <xquic/xquic.h>

#ifdef WIN32
int gettimeofday(struct timeval *tv, struct timezone *tz);
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

