/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef _XQC_TEST_LOG_H_INCLUDED_
#define _XQC_TEST_LOG_H_INCLUDED_

#include <stddef.h>

/* Write up to XQC_MAX_LOG_LEN bytes and a newline; no NUL is required. */
int xqc_test_log_write(int fd, const void *buf, size_t size);

#endif
