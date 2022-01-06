
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_RANDOM_H_INCLUDED_
#define _XQC_RANDOM_H_INCLUDED_

#include <sys/types.h>
#include <xquic/xquic_typedef.h>
#include "src/common/xqc_str.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_common.h"
#ifdef WIN32
#include <wincrypt.h>
#endif


typedef struct xqc_random_generator_s {
    /* for random */
    xqc_int_t               rand_fd;           /* init_value: -1 */
    off_t                   rand_buf_offset;   /* used offset */
    size_t                  rand_buf_size;     /* total buffer size */
    xqc_str_t               rand_buf;          /* buffer for random bytes*/

    xqc_log_t              *log;

#ifdef WIN32
    HCRYPTPROV              hProvider;
#endif
} xqc_random_generator_t;

xqc_int_t xqc_get_random(xqc_random_generator_t *rand_gen, u_char *buf, size_t need_len);
xqc_random_generator_t *xqc_random_generator_create(xqc_log_t *log);
void xqc_random_generator_destroy(xqc_random_generator_t *rand_gen);


#endif /* _XQC_RANDOM_H_INCLUDED_ */

