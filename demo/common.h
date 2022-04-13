/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/socket.h>

/* definition for connection */
#define DEFAULT_SERVER_ADDR "127.0.0.1"
#define DEFAULT_SERVER_PORT 8443

#define CIPHER_SUIT_LEN     256
#define TLS_GROUPS_LEN      64

#define PATH_LEN            512
#define RESOURCE_LEN        256
#define AUTHORITY_LEN       128
#define URL_LEN             512

#define RING_QUEUE_ELE_MAX_NUM      (2 * 1024)
#define RING_QUEUE_ELE_BUF_SIZE     (2 * 1024)

/* the congestion control types */
typedef enum cc_type_s {
    CC_TYPE_BBR,
    CC_TYPE_CUBIC,
    CC_TYPE_RENO,
    CC_TYPE_BBR2
} CC_TYPE;



/* request method */
typedef enum request_method_e {
    REQUEST_METHOD_GET,
    REQUEST_METHOD_POST,
} REQUEST_METHOD;

static char method_s[][16] = {
    {"GET"}, 
    {"POST"}
};

static const char *line_break = "\n";

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


static int
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

typedef struct {
    struct sockaddr_storage addr;
    socklen_t addr_len;
} xqc_demo_addr_info_t;

typedef struct {
    size_t data_size;
    uint8_t data_buf[0];
} xqc_demo_ring_queue_element_t;

typedef struct {
    void **p;
    size_t element_max_num;
    size_t element_buf_size;
    size_t element_num;
    size_t read_idx;
    size_t write_idx;
} xqc_demo_ring_queue_t;

void
xqc_demo_ring_queue_init(xqc_demo_ring_queue_t *ring_queue,
                         size_t element_max_num, size_t element_buf_size);
void
xqc_demo_ring_queue_free(xqc_demo_ring_queue_t *ring_queue);

/* return: 0, ok; 1, queue full; -1 error */
int
xqc_demo_ring_queue_push(xqc_demo_ring_queue_t* ring_queue,
                         uint8_t* data_buf, size_t data_size);

/* return: 0, ok; 1, queue full; -1 error */
int
xqc_demo_ring_queue_push2(xqc_demo_ring_queue_t* ring_queue,
                          uint8_t* data_hdr, size_t data_hdr_size,
                          uint8_t* data_body, size_t data_body_size);

/* return: 0, ok; 1, queue empty; -1 error */
int
xqc_demo_ring_queue_pop(xqc_demo_ring_queue_t *ring_queue,
                        uint8_t* data_buf, size_t buf_size, size_t *out_data_size);

#endif
