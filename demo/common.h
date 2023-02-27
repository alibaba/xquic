/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

/* definition for connection */
#define DEFAULT_SERVER_ADDR "127.0.0.1"
#define DEFAULT_SERVER_PORT 8443

#define CIPHER_SUIT_LEN     256
#define TLS_GROUPS_LEN      64

#define PATH_LEN            512
#define RESOURCE_LEN        256
#define AUTHORITY_LEN       128
#define URL_LEN             512

/* the congestion control types */
typedef enum cc_type_s {
    CC_TYPE_BBR,
    CC_TYPE_CUBIC,
    CC_TYPE_RENO
} CC_TYPE;



/* request method */
typedef enum request_method_e {
    REQUEST_METHOD_GET,
    REQUEST_METHOD_POST,
} REQUEST_METHOD;

char method_s[][16] = {
    {"GET"}, 
    {"POST"}
};

const char *line_break = "\n";

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


int
xqc_demo_read_file_data(char * data, size_t data_len, char *filename)
{
    int ret = 0;
    size_t total_len, read_len;
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        ret = -1;
        goto end;
    }

    fseek(fp, 0 , SEEK_END);
    total_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (total_len > data_len) {
        ret = -1;
        goto end;
    }

    read_len = fread(data, 1, total_len, fp);
    if (read_len != total_len) {
        ret = -1;
        goto end;
    }

    ret = read_len;

end:
    if (fp) {
        fclose(fp);
    }
    return ret;
}


static inline uint64_t
xqc_demo_now()
{
    /* get microsecond unit time */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
    return  ul;
}


#endif
