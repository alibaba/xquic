/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <errno.h>
#include <string.h>
#include "src/common/xqc_log.h"
#include "test_log.h"

#ifdef XQC_SYS_WINDOWS
#include <io.h>
#else
#include <unistd.h>
#endif

int
xqc_test_log_write(int fd, const void *buf, size_t size)
{
    unsigned char  line[XQC_MAX_LOG_LEN + 1];
    unsigned char *p = line;

    if (size > XQC_MAX_LOG_LEN) {
        errno = EINVAL;
        return -1;
    }
    if (size != 0) {
        memcpy(line, buf, size);
    }
    line[size++] = '\n';

    while (size != 0) {
#ifdef XQC_SYS_WINDOWS
        ssize_t n = _write(fd, p, (unsigned int) size);
#else
        ssize_t n = write(fd, p, size);
#endif
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }

        p += n;
        size -= n;
    }

    return 0;
}
