/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H


#include <memory.h>
#include <stdio.h>
#include <xquic/xquic_typedef.h>

/* definition for connection */
#define DEFAULT_SERVER_ADDR "127.0.0.1"
#define DEFAULT_SERVER_PORT 8443

#define CIPHER_SUIT_LEN     256
#define TLS_GROUPS_LEN      64

#define PATH_LEN            1024
#define RESOURCE_LEN        1024
#define AUTHORITY_LEN       128
#define URL_LEN             1024

/* the congestion control types */
typedef enum cc_type_s {
    CC_TYPE_BBR,
    CC_TYPE_CUBIC,
    CC_TYPE_RENO,
    CC_TYPE_COPA
} CC_TYPE;



/* request method */
typedef enum request_method_e {
    REQUEST_METHOD_GET,
    REQUEST_METHOD_POST,
} REQUEST_METHOD;

extern char method_s[][16];


static size_t READ_FILE_BUF_LEN = 2 *1024 * 1024;

#define DEBUG ;
// #define DEBUG printf("%s:%d (%s)\n",__FILE__, __LINE__ ,__FUNCTION__);


#define RSP_HDR_BUF_LEN 32
typedef enum h3_hdr_type {
    /* rsp */
    H3_HDR_STATUS,
    H3_HDR_CONTENT_TYPE,
    H3_HDR_CONTENT_LENGTH,
    H3_HDR_METHOD,
    H3_HDR_SCHEME,
    H3_HDR_HOST,
    H3_HDR_PATH,

    H3_HDR_CNT
} H3_HDR_TYPE;


extern long xqc_random(void);
extern xqc_usec_t xqc_now();


int xqc_mini_read_file_data(char * data, size_t data_len, char *filename);

#endif
