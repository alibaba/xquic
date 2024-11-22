/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "platform.h"

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
