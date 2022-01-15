/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include "src/common/xqc_random.h"
#include "src/common/xqc_str.h"
#include "src/common/xqc_log.h"

#define XQC_RANDOM_BUFFER_SIZE 4096

xqc_random_generator_t * 
xqc_random_generator_create(xqc_log_t *log)
{
    xqc_random_generator_t *rand_gen = xqc_malloc(sizeof(xqc_random_generator_t));
    if (rand_gen == NULL) {
        return NULL;
    }

    xqc_memzero(rand_gen, sizeof(xqc_random_generator_t));
    rand_gen->rand_buf.data = xqc_malloc(XQC_RANDOM_BUFFER_SIZE);
    if (rand_gen->rand_buf.data == NULL) {
        xqc_free(rand_gen);
        return NULL;
    }
    rand_gen->rand_buf_size = XQC_RANDOM_BUFFER_SIZE;
    rand_gen->rand_fd = -1;
    rand_gen->log = log;
#ifdef WIN32
    rand_gen->hProvider = 0;
    int res = CryptAcquireContextW(&rand_gen->hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    assert(res);
#endif
    return rand_gen;
}

void 
xqc_random_generator_destroy(xqc_random_generator_t *rand_gen)
{
#ifdef WIN32
    CryptReleaseContext(rand_gen->hProvider, 0);
#endif
    xqc_free(rand_gen->rand_buf.data);
    xqc_free(rand_gen);
}

xqc_int_t
xqc_get_random(xqc_random_generator_t *rand_gen, u_char *buf, size_t need_len)
{
#ifndef WIN32
    size_t total_read = 0;
    ssize_t bytes_read = 0;

    if ((size_t)rand_gen->rand_buf_offset >= rand_gen->rand_buf.len
        || rand_gen->rand_buf.len - (size_t)rand_gen->rand_buf_offset <= need_len) {

        /* not enough in rand_buf */
        if (rand_gen->rand_fd == -1) {
            rand_gen->rand_fd = open("/dev/urandom", O_RDONLY|O_NONBLOCK);
            if (rand_gen->rand_fd == -1) {
                xqc_log(rand_gen->log, XQC_LOG_WARN, "|random|can not open /dev/urandom|\n");
                return XQC_ERROR;
            }
        }

        total_read = 0;

        while (total_read < rand_gen->rand_buf_size) {

            bytes_read = read(rand_gen->rand_fd, 
                              rand_gen->rand_buf.data + total_read, 
                              rand_gen->rand_buf_size - total_read);

            if (bytes_read == -1) {
                if (errno == EINTR) {
                    continue;
                }

                if (errno == EAGAIN) {
                    break;
                }
            }

            if (bytes_read <= 0) {

                xqc_log(rand_gen->log, XQC_LOG_WARN, "|random|fail to read bytes from /dev/urandom|");

                close(rand_gen->rand_fd);
                rand_gen->rand_fd = -1;
                break;
            }

            total_read += bytes_read;
        }
 
        if (total_read < need_len) {
            xqc_log(rand_gen->log, XQC_LOG_WARN,
                    "|random|can not generate rand buf|%zu|%zu|", total_read, need_len);
            return XQC_ERROR;            
        }
        
        rand_gen->rand_buf_offset = 0;
        rand_gen->rand_buf.len = total_read;   
    }

    xqc_memcpy(buf, rand_gen->rand_buf.data + rand_gen->rand_buf_offset, need_len);

    rand_gen->rand_buf_offset += need_len;
#else
    DWORD result = CryptGenRandom(rand_gen->hProvider, need_len, buf);
    assert(result);
#endif
    return XQC_OK;
}

