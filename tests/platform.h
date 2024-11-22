/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#include <errno.h>

#if defined(_WIN64) || defined(WIN64) || defined(_WIN32) || defined(WIN32)
#define XQC_SYS_WINDOWS
#endif

#ifdef XQC_SYS_WINDOWS
# define EAGAIN  WSAEWOULDBLOCK
# define EINTR WSAEINTR
#endif


/**
 * @brief get system last errno
 * 
 * @return int 
 */
int get_sys_errno();

void set_sys_errno(int err);

/**
 * @brief init platform env if necessary
 * 
 */
void xqc_platform_init_env();
#endif
