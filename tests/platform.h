/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef PLATFORM_H
#define PLATFORM_H

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
int get_sys_errno()
{
    int err = 0;
#ifdef XQC_SYS_WINDOWS
    err = WSAGetLastError();
#else
    err = errno;
#endif
    return err;
}

void set_sys_errno(int err)
{
#ifdef XQC_SYS_WINDOWS
    WSASetLastError(err);
#else
    errno = err;
#endif
}

/**
 * @brief init platform env if necessary
 * 
 */
void xqc_platform_init_env()
{
    int result = 0;

 #ifdef XQC_SYS_WINDOWS  
    // Initialize Winsock
    WSADATA wsaData;
    if ((result = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0) {
        printf("WSAStartup failed with error %d\n", result);
        exit(1);
    }
#endif

}
#endif
