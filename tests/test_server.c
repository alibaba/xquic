/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <event2/event.h>
#include <inttypes.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>

#include "platform.h"

#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <sys/wait.h>
#include <getopt.h>
#else
#include "getopt.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Bcrypt.lib")
#endif

#define XQC_FIRST_OCTET 1
int
printf_null(const char *format, ...)
{
    return 0;
}


#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 8443

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)

#define XQC_ALPN_TRANSPORT "transport"

#define XQC_MAX_LOG_LEN 2048

#define XQC_TEST_DGRAM_BATCH_SZ 32

extern long xqc_random(void);
extern xqc_usec_t xqc_now();


typedef struct user_datagram_block_s {
    unsigned char *data;
    size_t         data_len;
    size_t         to_send_size;
    size_t         data_sent;
    size_t         data_recv;
    size_t         data_lost;
    size_t         dgram_lost;
} user_dgram_blk_t;


typedef struct xqc_quic_lb_ctx_s {
    uint8_t    sid_len;
    uint8_t    sid_buf[XQC_MAX_CID_LEN];
    uint8_t    conf_id;
    uint8_t    cid_len;
    uint8_t    cid_buf[XQC_MAX_CID_LEN];
    uint8_t    lb_cid_key[XQC_LB_CID_KEY_LEN];
    int        lb_cid_enc_on;
} xqc_quic_lb_ctx_t;


typedef struct user_stream_s {
    xqc_stream_t            *stream;
    xqc_h3_request_t        *h3_request;
    uint64_t                 send_offset;
    int                      header_sent;
    int                      header_recvd;
    char                    *send_body;
    size_t                   send_body_len;
    size_t                   send_body_max;
    char                    *recv_body;
    size_t                   recv_body_len;
    FILE                    *recv_body_fp;
    xqc_h3_ext_bytestream_t *h3_ext_bs;
    int                      recv_fin;
    int                      echo_fin;

    int                      snd_times;
    int                      rcv_times;
    struct event            *ev_timeout;
} user_stream_t;

typedef struct user_conn_s {
    struct event        *ev_timeout;
    struct sockaddr_in6  peer_addr;
    socklen_t            peer_addrlen;
    xqc_cid_t            cid;

    user_dgram_blk_t   *dgram_blk;
    size_t              dgram_mss;
    uint8_t             dgram_not_supported;

    xqc_connection_t   *quic_conn;
    xqc_h3_conn_t      *h3_conn;
} user_conn_t;

typedef struct xqc_server_ctx_s {
    int fd;
    xqc_engine_t        *engine;
    struct sockaddr_in6  local_addr;
    socklen_t            local_addrlen;
    struct event        *ev_socket;
    struct event        *ev_engine;
    int                  log_fd;
    int                  keylog_fd;
    xqc_quic_lb_ctx_t    quic_lb_ctx;
} xqc_server_ctx_t;

typedef struct {
    double p;
    int val;
} cdf_entry_t;

xqc_server_ctx_t ctx;
struct event_base *eb;
xqc_data_qos_level_t g_dgram_qos_level;
int g_pmtud_on;
int g_send_dgram;
int g_max_dgram_size;
int g_send_body_size_from_cdf;
cdf_entry_t *cdf_list;
int cdf_list_size;
int g_echo = 0;
int g_send_body_size;
int g_send_body_size_defined;
int g_save_body;
int g_read_body;
int g_spec_url;
//99 pure fin
int g_test_case;
int g_ipv6;
int g_batch=0;
int g_lb_cid_encryption_on = 0;
int g_enable_multipath = 0;
// xqc_multipath_version_t g_multipath_version = XQC_MULTIPATH_05;
int g_enable_reinjection = 0;
int g_spec_local_addr = 0;
int g_mpshell = 0;
int g_endless_sending = 0;
int g_enable_fec = 0;
double g_copa_ai = 1.0;
double g_copa_delta = 0.05;
int g_enable_h3_ext = 1;
int g_mp_backup_mode = 0;
char g_write_file[256];
char g_read_file[256];
char g_log_path[256];
char g_host[64] = "test.xquic.com";
char g_path[256] = "/path/resource";
char g_scheme[8] = "https";
char g_url[256];
char g_sid[XQC_MAX_CID_LEN];
char g_lb_cid_enc_key[XQC_LB_CID_KEY_LEN];
size_t g_sid_len = 0;
size_t g_lb_cid_enc_key_len = 0;
static uint64_t last_snd_ts;


#define XQC_TEST_LONG_HEADER_LEN 32769
char test_long_value[XQC_TEST_LONG_HEADER_LEN] = {'\0'};

/*
 CDF file format:
 N (N lines)
 p1(0) v1(0)
 p2 v2
 ....
 pN(1.0) vN
*/
static int
load_cdf(char *cdf_file)
{
    FILE *fp = fopen(cdf_file, "r");
    if (fp == NULL) {
        return -1;
    }
    int n;
    fscanf(fp, "%d", &n);
    cdf_list_size = n;
    cdf_list = malloc(sizeof(cdf_entry_t) * cdf_list_size);
    while (n--) {
        fscanf(fp, "%lf%d", &cdf_list[cdf_list_size - n - 1].p, &cdf_list[cdf_list_size - n - 1].val);
    }
    return 0;
}

static void
destroy_cdf()
{
    if (cdf_list != NULL) {
        free(cdf_list);
        cdf_list = NULL;
    }
}

static int
get_val_from_cdf_by_p(double p)
{
    int last_entry_id = -1, i;
    double p0 = 0, p1 = 0;
    int v0 = 0, v1 = 0;
    int v = 0;
    for (i = 0; i < cdf_list_size; i++) {
        if (p > cdf_list[i].p) {
            last_entry_id = i;
            p0 = cdf_list[i].p;
            v0 = cdf_list[i].val;
        } else {
            //linear interpolation
            p1 = cdf_list[i].p;
            v1 = cdf_list[i].val;
            v = v0 + (int)(((v1 - v0) / (p1 - p0)) * (p - p0));
            break;
        }
    }
    if (v == 0) {
        v = 1;
    }
    return v;
}

static int
get_random_from_cdf()
{
    int r = 1 + (xqc_random() % 1000);
    double p = r * 1.0 / 1000; // 0.001 ~ 1
    return get_val_from_cdf_by_p(p);
}


static void 
xqc_server_datagram_send(user_conn_t *user_conn)
{
    if (user_conn->dgram_not_supported) {
        // exit
        printf("[dgram]|peer_does_not_support_datagram|\n");
        xqc_conn_close(ctx.engine, &user_conn->cid);
        return;
    }

    user_dgram_blk_t *dgram_blk = user_conn->dgram_blk;
    int ret;

    if (g_send_dgram == 1) {
        uint64_t dgram_id;
        while (dgram_blk->data_sent < dgram_blk->to_send_size) {
            size_t dgram_size = dgram_blk->to_send_size - dgram_blk->data_sent;
            if (dgram_size > user_conn->dgram_mss) {
                dgram_size = user_conn->dgram_mss;
            }
            dgram_blk->data[dgram_blk->data_sent] = 0x31;
            ret = xqc_datagram_send(user_conn->quic_conn, dgram_blk->data + dgram_blk->data_sent, dgram_size, &dgram_id, g_dgram_qos_level);
            if (ret == -XQC_EAGAIN) {
                printf("[dgram]|retry_datagram_send_later|\n");
                return;
            } else if (ret == -XQC_EDGRAM_TOO_LARGE) {
                printf("[dgram]|trying_to_send_an_oversized_datagram|recorded_mss:%zu|send_size:%zu|current_mss:%zu|\n", user_conn->dgram_mss, dgram_size, xqc_datagram_get_mss(user_conn->quic_conn));
                xqc_conn_close(ctx.engine, &user_conn->cid);
                return;
            } else if (ret < 0) {
                printf("[dgram]|send_datagram_error|err_code:%d|\n", ret);
                xqc_conn_close(ctx.engine, &user_conn->cid);
                return;
            }
            //printf("[dgram]|send_one_datagram|id:%"PRIu64"|size:%zu|\n", dgram_id, dgram_size);
            dgram_blk->data_sent += dgram_size;
        }
    } else if (g_send_dgram == 2) {
        struct iovec iov[XQC_TEST_DGRAM_BATCH_SZ];
        uint64_t dgram_id_list[XQC_TEST_DGRAM_BATCH_SZ];
        size_t bytes_in_batch = 0;
        int batch_cnt = 0;
        while ((dgram_blk->data_sent + bytes_in_batch) < dgram_blk->to_send_size) {
            size_t dgram_size = dgram_blk->to_send_size - dgram_blk->data_sent - bytes_in_batch;
            size_t succ_sent = 0, succ_sent_bytes = 0;
            if (dgram_size > user_conn->dgram_mss) {
                dgram_size = user_conn->dgram_mss;
            }
            iov[batch_cnt].iov_base = dgram_blk->data + dgram_blk->data_sent + bytes_in_batch;
            iov[batch_cnt].iov_len = dgram_size;
            dgram_blk->data[dgram_blk->data_sent + bytes_in_batch] = 0x31;
            bytes_in_batch += dgram_size;
            batch_cnt++;
            if ((bytes_in_batch + dgram_blk->data_sent) == dgram_blk->to_send_size
                || batch_cnt == XQC_TEST_DGRAM_BATCH_SZ) 
            {
                ret = xqc_datagram_send_multiple(user_conn->quic_conn, iov, dgram_id_list, batch_cnt, &succ_sent, &succ_sent_bytes, g_dgram_qos_level);
                if (ret == -XQC_EDGRAM_TOO_LARGE) {
                    printf("[dgram]|trying_to_send_an_oversized_datagram|recorded_mss:%zu|send_size:%zu|current_mss:%zu|\n", user_conn->dgram_mss, iov[succ_sent].iov_len, xqc_datagram_get_mss(user_conn->quic_conn));
                    xqc_conn_close(ctx.engine, &user_conn->cid);
                    return;
                } else if (ret < 0 && ret != -XQC_EAGAIN) {
                    printf("[dgram]|send_datagram_multiple_error|err_code:%d|\n", ret);
                    xqc_conn_close(ctx.engine, &user_conn->cid);
                    return;
                }

                // for (int i = 0; i < succ_sent; i++) {
                //     printf("[dgram]|send_one_datagram|id:%"PRIu64"|size:%zu|\n", dgram_id_list[i], iov[i].iov_len);
                // }

                // printf("[dgram]|datagrams_sent_in_a_batch|cnt:%zu|size:%zu|\n", succ_sent, succ_sent_bytes);
                
                dgram_blk->data_sent += succ_sent_bytes;
                
                if (ret == -XQC_EAGAIN) {
                    printf("[dgram]|retry_datagram_send_multiple_later|\n");
                    return;
                } 

                bytes_in_batch = 0;
                batch_cnt = 0;
            }
        }

    }
}

static void
xqc_server_datagram_mss_updated_callback(xqc_connection_t *conn, 
    size_t mss, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    if (user_conn->dgram_mss == 0) {
        if (g_test_case == 200 || g_test_case == 201) {
            printf("[dgram-200]|1RTT|initial_mss:%zu|\n", mss);
        }

    } else {
        printf("[dgram]|1RTT|updated_mss:%zu|\n", mss);
    }

    user_conn->dgram_mss = mss;

    if (!user_conn->dgram_not_supported && user_conn->dgram_mss == 0) {
        user_conn->dgram_not_supported = 1;
    }
}

static void
xqc_server_datagram_read_callback(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t dgram_ts)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;

    if (g_send_dgram) {
        if (g_echo) {
            uint64_t dgram_id;
            int ret;
            if (user_conn->dgram_blk->data_recv + data_len > user_conn->dgram_blk->data_len) {
                //expand buffer size
                size_t new_len = (user_conn->dgram_blk->data_recv + data_len) << 1;
                unsigned char *new_data = calloc(1, new_len);
                memcpy(new_data, user_conn->dgram_blk->data, user_conn->dgram_blk->data_recv);
                if (user_conn->dgram_blk->data) {
                    free(user_conn->dgram_blk->data);
                }
                user_conn->dgram_blk->data = new_data;
                user_conn->dgram_blk->data_len = new_len;
            }
            memcpy(user_conn->dgram_blk->data + user_conn->dgram_blk->data_recv, data, data_len);
            user_conn->dgram_blk->data_recv += data_len;
            user_conn->dgram_blk->to_send_size = user_conn->dgram_blk->data_recv;
            
        } else {
            user_conn->dgram_blk->data_recv += data_len;
        }
    }

    if (g_send_dgram){
        if (user_conn->dgram_blk->data_sent < user_conn->dgram_blk->data_len) {
           xqc_server_datagram_send(user_conn); 
        }
    }
}

static void 
xqc_server_datagram_write_callback(xqc_connection_t *conn, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    if (g_send_dgram) {
        xqc_server_datagram_send(user_conn);
    }
}

static void 
xqc_server_datagram_acked_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{

}

static int 
xqc_server_datagram_lost_callback(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    //user_conn->dgram_blk->data_lost += data_len;
    user_conn->dgram_blk->dgram_lost++;
    return 0;
}


static void 
xqc_server_h3_ext_datagram_send(user_conn_t *user_conn)
{
    if (user_conn->dgram_not_supported) {
        // exit
        printf("[h3-dgram]|peer_does_not_support_datagram|\n");
        xqc_h3_conn_close(ctx.engine, &user_conn->cid);
        return;
    }

    user_dgram_blk_t *dgram_blk = user_conn->dgram_blk;
    int ret;

    if (g_send_dgram == 1) {
        uint64_t dgram_id;
        while (dgram_blk->data_sent < dgram_blk->to_send_size) {
            size_t dgram_size = dgram_blk->to_send_size - dgram_blk->data_sent;
            if (dgram_size > user_conn->dgram_mss) {
                dgram_size = user_conn->dgram_mss;
            }
            dgram_blk->data[dgram_blk->data_sent] = 0x31;
            ret = xqc_h3_ext_datagram_send(user_conn->h3_conn, dgram_blk->data + dgram_blk->data_sent, dgram_size, &dgram_id, g_dgram_qos_level);
            if (ret == -XQC_EAGAIN) {
                printf("[h3-dgram]|retry_datagram_send_later|\n");
                return;
            } else if (ret == -XQC_EDGRAM_TOO_LARGE ) {
                printf("[h3-dgram]|trying_to_send_an_oversized_datagram|recorded_mss:%zu|send_size:%zu|current_mss:%zu|\n", user_conn->dgram_mss, dgram_size, xqc_h3_ext_datagram_get_mss(user_conn->h3_conn));
                xqc_h3_conn_close(ctx.engine, &user_conn->cid);
                return;
            } else if (ret < 0) {
                printf("[h3-dgram]|send_datagram_error|err_code:%d|\n", ret);
                xqc_h3_conn_close(ctx.engine, &user_conn->cid);
                return;
            }
            //printf("[dgram]|send_one_datagram|id:%"PRIu64"|size:%zu|\n", dgram_id, dgram_size);
            dgram_blk->data_sent += dgram_size;
        }
    } else if (g_send_dgram == 2) {
        struct iovec iov[XQC_TEST_DGRAM_BATCH_SZ];
        uint64_t dgram_id_list[XQC_TEST_DGRAM_BATCH_SZ];
        size_t bytes_in_batch = 0;
        int batch_cnt = 0;
        while ((dgram_blk->data_sent + bytes_in_batch) < dgram_blk->to_send_size) {
            size_t dgram_size = dgram_blk->to_send_size - dgram_blk->data_sent - bytes_in_batch;
            size_t succ_sent = 0, succ_sent_bytes = 0;
            if (dgram_size > user_conn->dgram_mss) {
                dgram_size = user_conn->dgram_mss;
            }
            iov[batch_cnt].iov_base = dgram_blk->data + dgram_blk->data_sent + bytes_in_batch;
            iov[batch_cnt].iov_len = dgram_size;
            dgram_blk->data[dgram_blk->data_sent + bytes_in_batch] = 0x31;
            bytes_in_batch += dgram_size;
            batch_cnt++;
            if ((bytes_in_batch + dgram_blk->data_sent) == dgram_blk->to_send_size
                || batch_cnt == XQC_TEST_DGRAM_BATCH_SZ) 
            {
                ret = xqc_h3_ext_datagram_send_multiple(user_conn->h3_conn, iov, dgram_id_list, batch_cnt, &succ_sent, &succ_sent_bytes, g_dgram_qos_level);
                if (ret == -XQC_EDGRAM_TOO_LARGE) {
                    printf("[h3-dgram]|trying_to_send_an_oversized_datagram|recorded_mss:%zu|send_size:%zu|current_mss:%zu|\n", user_conn->dgram_mss, iov[succ_sent].iov_len, xqc_h3_ext_datagram_get_mss(user_conn->h3_conn));
                    xqc_h3_conn_close(ctx.engine, &user_conn->cid);
                    return;
                } else if (ret < 0 && ret != -XQC_EAGAIN) {
                    printf("[h3-dgram]|send_datagram_multiple_error|err_code:%d|\n", ret);
                    xqc_h3_conn_close(ctx.engine, &user_conn->cid);
                    return;
                }

                // for (int i = 0; i < succ_sent; i++) {
                //     printf("[dgram]|send_one_datagram|id:%"PRIu64"|size:%zu|\n", dgram_id_list[i], iov[i].iov_len);
                // }

                // printf("[dgram]|datagrams_sent_in_a_batch|cnt:%zu|size:%zu|\n", succ_sent, succ_sent_bytes);
                
                dgram_blk->data_sent += succ_sent_bytes;
                
                if (ret == -XQC_EAGAIN) {
                    printf("[h3-dgram]|retry_datagram_send_multiple_later|\n");
                    return;
                } 

                bytes_in_batch = 0;
                batch_cnt = 0;
            }
        }

    }
}

static void
xqc_server_h3_ext_datagram_mss_updated_callback(xqc_h3_conn_t *conn, size_t mss, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    if (user_conn->dgram_mss == 0) {
        if (g_test_case == 200 || g_test_case == 201) {
            printf("[h3-dgram-200]|1RTT|initial_mss:%zu|\n", mss);
        }

    } else {
        printf("[h3-dgram]|1RTT|updated_mss:%zu|\n", mss);
    }

    user_conn->dgram_mss = mss;

    if (!user_conn->dgram_not_supported && user_conn->dgram_mss == 0) {
        user_conn->dgram_not_supported = 1;
    }
}

static void
xqc_server_h3_ext_datagram_read_callback(xqc_h3_conn_t *conn, const void *data, size_t data_len, void *user_data, uint64_t ts)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;

    uint8_t dgram_type;
    uint32_t dgram_id;
    uint64_t timestamp;

    if (data_len >= 13) {
        dgram_type = *(uint8_t*)data;
        dgram_id = *(uint32_t*)((uint8_t *)data + 1);
        timestamp = *(uint64_t*)((uint8_t *)data + 5);

        if (dgram_type == 0x32) {
            printf("[h3-dgram-benchmark]|dgram_id:%u|time:%"PRIu64"|\n", dgram_id, xqc_now() - timestamp);
        }
    }



    if (g_send_dgram) {
        if (g_echo) {
            uint64_t dgram_id;
            int ret;
            if (user_conn->dgram_blk->data_recv + data_len > user_conn->dgram_blk->data_len) {
                //expand buffer size
                size_t new_len = (user_conn->dgram_blk->data_recv + data_len) << 1;
                unsigned char *new_data = calloc(1, new_len);
                memcpy(new_data, user_conn->dgram_blk->data, user_conn->dgram_blk->data_recv);
                if (user_conn->dgram_blk->data) {
                    free(user_conn->dgram_blk->data);
                }
                user_conn->dgram_blk->data = new_data;
                user_conn->dgram_blk->data_len = new_len;
            }
            memcpy(user_conn->dgram_blk->data + user_conn->dgram_blk->data_recv, data, data_len);
            user_conn->dgram_blk->data_recv += data_len;
            user_conn->dgram_blk->to_send_size = user_conn->dgram_blk->data_recv;
            
        } else {
            user_conn->dgram_blk->data_recv += data_len;
        }
    }

    // printf("recv:%zd, to_send:%zd, data_len: %zd, sent: %zd\n", user_conn->dgram_blk->data_recv, user_conn->dgram_blk->to_send_size, user_conn->dgram_blk->data_len, user_conn->dgram_blk->data_sent);

    if (g_send_dgram){
        if (user_conn->dgram_blk->data_sent < user_conn->dgram_blk->to_send_size) {
           xqc_server_h3_ext_datagram_send(user_conn); 
        }
    }
}

static void 
xqc_server_h3_ext_datagram_write_callback(xqc_h3_conn_t *conn, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("h3 datagram write notify!\n");
    if (g_send_dgram) {
        xqc_server_h3_ext_datagram_send(user_conn);
    }
}

static void 
xqc_server_h3_ext_datagram_acked_callback(xqc_h3_conn_t *conn, uint64_t dgram_id, void *user_data)
{
    
}

static int 
xqc_server_h3_ext_datagram_lost_callback(xqc_h3_conn_t *conn, uint64_t dgram_id, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    user_conn->dgram_blk->data_lost += 0;
    user_conn->dgram_blk->dgram_lost++;
    return 0;
}

void
xqc_server_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) user_data;

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

}

int
read_file_data( char * data, size_t data_len, char *filename)
{
    int ret = 0;
    size_t total_len, read_len;
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        ret = -1;
        goto end;
    }

    fseek(fp, 0, SEEK_END);
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

int
xqc_server_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t*)user_data;

    user_conn->quic_conn = conn;
    user_conn->dgram_blk = calloc(1, sizeof(user_dgram_blk_t));
    user_conn->dgram_blk->data_recv = 0;
    user_conn->dgram_blk->data_sent = 0;
    
    xqc_datagram_set_user_data(conn, user_conn);

    if (g_send_dgram) {
        user_conn->dgram_blk->data = calloc(1, g_send_body_size);
        user_conn->dgram_blk->data_len = g_send_body_size;
        if (!g_echo) {
            user_conn->dgram_blk->to_send_size = g_send_body_size;
        }
    }

    return 0;
}

int
xqc_server_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *)user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, lost_dgram_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s, alpn:%s\n",
           stats.send_count, stats.lost_count, stats.lost_dgram_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info, stats.alpn);

    printf("[dgram]|recv_dgram_bytes:%zu|sent_dgram_bytes:%zu|lost_dgram_bytes:%zu|lost_cnt:%zu|\n", 
           user_conn->dgram_blk->data_recv, user_conn->dgram_blk->data_sent,
           user_conn->dgram_blk->data_lost, user_conn->dgram_blk->dgram_lost);

    if (user_conn->dgram_blk) {
        if (user_conn->dgram_blk->data) {
            free(user_conn->dgram_blk->data);
        }
        free(user_conn->dgram_blk);
    }

    free(user_conn);

    if (g_mpshell) {
        event_base_loopbreak(eb);
        printf("xqc_server_conn_close_notify\n");
    }

    return 0;
}

void
xqc_server_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;
    printf("datagram_mss:%zd\n", xqc_datagram_get_mss(conn));
}

void
xqc_server_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *) user_data;

    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));

    printf("====>RETIRE SCID:%s\n", xqc_scid_str(ctx.engine, retire_cid));
    printf("====>SCID:%s\n", xqc_scid_str(ctx.engine, new_cid));
    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, new_cid));

}


int
xqc_server_stream_send(xqc_stream_t *stream, void *user_data)
{
    ssize_t ret;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;

        /* priority: echo > specified size > specified file > default size */
        if (g_echo) {
            user_stream->send_body = malloc(user_stream->recv_body_len);
            memcpy(user_stream->send_body, user_stream->recv_body, user_stream->recv_body_len);
            user_stream->send_body_len = user_stream->recv_body_len;

        } else {
            if (g_send_body_size_defined) {
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;

            } else if (g_read_body) {
                user_stream->send_body = malloc(user_stream->send_body_max);
                ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
                if (ret < 0) {
                    printf("read body error\n");
                    return -1;

                } else {
                    user_stream->send_body_len = ret;
                }

            } else {
                if (g_send_body_size_from_cdf == 1) {
                    g_send_body_size = get_random_from_cdf();
                    printf("send_request, size_from_cdf:%d\n", g_send_body_size);
                }
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;
            }
        }
    }

    if (user_stream->send_offset < user_stream->send_body_len) {
        if (g_endless_sending) {
            ret = xqc_stream_send(stream, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, 0);
            if (ret < 0) {
                printf("xqc_stream_send error %zd\n", ret);
                return 0;

            } else {
                printf("xqc_stream_send sent_bytes=%zd\n", ret);
            }
        } else {
            ret = xqc_stream_send(stream, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, 1);
            if (ret < 0) {
                printf("xqc_stream_send error %zd\n", ret);
                return 0;

            } else {
                user_stream->send_offset += ret;
                printf("xqc_stream_send offset=%"PRIu64"\n", user_stream->send_offset);
            }
        }
    }

    if (g_test_case == 12 /* test linger close */
        && user_stream->send_offset == user_stream->send_body_len)
    {
        user_conn_t *user_conn = xqc_get_conn_user_data_by_stream(stream);
        xqc_conn_close(ctx.engine, &user_conn->cid);
        printf("xqc_conn_close\n");
    }

    return 0;
}

int
xqc_server_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    int ret = 0;

    user_stream_t *user_stream = calloc(1, sizeof(*user_stream));
    user_stream->stream = stream;
    xqc_stream_set_user_data(stream, user_stream);

    if (g_test_case == 99) {
        xqc_stream_send(stream, NULL, 0, 1);
    }

    if (g_test_case == 15) {
        return -1;
    }

    return 0;
}

int
xqc_server_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;
    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    return 0;
}

int
xqc_server_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    int ret = xqc_server_stream_send(stream, user_data);
    return ret;
}

int
xqc_server_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    //DEBUG;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if (g_echo && user_stream->recv_body == NULL) {
        user_stream->recv_body = malloc(MAX_BUF_SIZE);
        if (user_stream->recv_body == NULL) {
            printf("recv_body malloc error\n");
            return -1;
        }
    }

    int save = g_save_body;

    if (save && user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen(g_write_file, "wb");
        if (user_stream->recv_body_fp == NULL) {
            printf("open error\n");
            return -1;
        }
    }

    char buff[4096] = {0};
    size_t buff_size = 4096;
    ssize_t read;
    ssize_t read_sum = 0;
    do {
        read = xqc_stream_recv(stream, buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_stream_recv error %zd\n", read);
            return 0;
        }
        read_sum += read;

        /* write received body to file */
        if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
            printf("fwrite error\n");
            return -1;
        }

        if (save) {
            fflush(user_stream->recv_body_fp);
        }

        /* write received body to memory */
        if (g_echo) {
            memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
        }
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    // mpshell
    // printf("xqc_stream_recv read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);

    if (fin) {
        xqc_server_stream_send(stream, user_data);
    }
    return 0;
}

int
xqc_server_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *conn_user_data)
{

    DEBUG;
    /* user_conn_t *user_conn = (xqc_server_ctx_t*)conn_user_data; */

    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));

    user_conn->h3_conn = h3_conn;
    user_conn->dgram_blk = calloc(1, sizeof(user_dgram_blk_t));
    user_conn->dgram_blk->data_recv = 0;
    user_conn->dgram_blk->data_sent = 0;
    
    xqc_h3_ext_datagram_set_user_data(h3_conn, user_conn);

    if (g_send_dgram) {
        user_conn->dgram_blk->data = calloc(1, g_send_body_size);
        user_conn->dgram_blk->data_len = g_send_body_size;
        if (!g_echo) {
            user_conn->dgram_blk->to_send_size = user_conn->dgram_blk->data_len;
        }
    }

    xqc_h3_conn_set_user_data(h3_conn, user_conn);

    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&user_conn->peer_addr,
                              sizeof(user_conn->peer_addr), &user_conn->peer_addrlen);

    memcpy(&user_conn->cid, cid, sizeof(*cid));
    return 0;
}

int
xqc_server_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *conn_user_data)
{

    DEBUG;
    user_conn_t *user_conn = (user_conn_t*)conn_user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, cid);
    printf("send_count:%u, lost_count:%u, tlp_count:%u, recv_count:%u, srtt:%"PRIu64" early_data_flag:%d, conn_err:%d, ack_info:%s, conn_info:%s, alpn:%s\n",
           stats.send_count, stats.lost_count, stats.tlp_count, stats.recv_count, stats.srtt, stats.early_data_flag, stats.conn_err, stats.ack_info, stats.conn_info, stats.alpn);

    printf("[h3-dgram]|recv_dgram_bytes:%zu|sent_dgram_bytes:%zu|lost_dgram_bytes:%zu|lost_cnt:%zu|\n", 
           user_conn->dgram_blk->data_recv, user_conn->dgram_blk->data_sent,
           user_conn->dgram_blk->data_lost, user_conn->dgram_blk->dgram_lost);

    if (user_conn->dgram_blk) {
        if (user_conn->dgram_blk->data) {
            free(user_conn->dgram_blk->data);
        }
        free(user_conn->dgram_blk);
    }

    free(user_conn);

    if (g_mpshell) {
        event_base_loopbreak(eb);
        printf("xqc_server_h3_conn_close_notify\n");
    }

    return 0;
}

void
xqc_server_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *conn_user_data)
{
    DEBUG;
    user_conn_t *user_conn = (user_conn_t *)conn_user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(ctx.engine, &user_conn->cid);
    printf("0rtt_flag:%d\n", stats.early_data_flag);
    printf("h3_datagram_mss:%zd\n", xqc_h3_ext_datagram_get_mss(h3_conn));


    /* pretend to create a server-inited http3 stream */
    if (g_test_case == 17) {
        xqc_stream_t * stream = xqc_stream_create_with_direction(
            xqc_h3_conn_get_xqc_conn(h3_conn), XQC_STREAM_BIDI, NULL);
        printf("--- server create stream\n");

        unsigned char szbuf[4096] = {0};
        xqc_stream_send(stream, szbuf, 4096, 1);

    }

}

void
xqc_server_h3_conn_update_cid_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *retire_cid,
    const xqc_cid_t *new_cid, void *conn_user_data)
{
    DEBUG;

    user_conn_t *user_conn = (user_conn_t *)conn_user_data;

    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));

    printf("====>RETIRE SCID:%s\n", xqc_scid_str(ctx.engine, retire_cid));
    printf("====>SCID:%s\n", xqc_scid_str(ctx.engine, new_cid));
    printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx.engine, new_cid));

}

int
xqc_server_bytestream_send(xqc_h3_ext_bytestream_t *h3_bs, user_stream_t *user_stream)
{
    int ret = 0;
    /* echo bytestream */
    if (user_stream->send_offset < user_stream->recv_body_len || (!user_stream->echo_fin && user_stream->recv_fin)) {
        ret = xqc_h3_ext_bytestream_send(h3_bs, user_stream->send_body + user_stream->send_offset, user_stream->recv_body_len - user_stream->send_offset, user_stream->recv_fin, g_dgram_qos_level);

        if (ret == -XQC_EAGAIN) {
            return ret;

        } else if (ret < 0) {
            printf("xqc_h3_ext_bytestream_send error %d\n", ret);
            return ret;

        } else {
            user_stream->snd_times++;
            user_stream->send_offset += ret;
            if (user_stream->recv_fin && user_stream->send_offset == user_stream->recv_body_len) {
                user_stream->echo_fin = 1;
            }
        }
    }

    return 0;
}

int xqc_h3_ext_bytestream_create_callback(xqc_h3_ext_bytestream_t *h3_ext_bs, 
	void *bs_user_data)
{
    user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
    user_stream->h3_ext_bs = h3_ext_bs;
    xqc_h3_ext_bytestream_set_user_data(h3_ext_bs, user_stream);

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;
        user_stream->send_body_len = user_stream->send_body_max;
        user_stream->send_body = malloc(user_stream->send_body_len);
        user_stream->send_offset = 0;
        user_stream->recv_body_len = 0;
        user_stream->recv_fin = 0;
    }

    if (g_test_case == 99) {
        xqc_h3_ext_bytestream_finish(h3_ext_bs);
    }

    printf("[bytestream]| stream: %"PRIu64" create callback|\n", xqc_h3_ext_bytestream_id(h3_ext_bs));

    return 0;
}

int xqc_h3_ext_bytestream_close_callback(xqc_h3_ext_bytestream_t *h3_ext_bs, 
	void *bs_user_data)
{
    //print stats
    xqc_h3_ext_bytestream_stats_t stats = xqc_h3_ext_bytestream_get_stats(h3_ext_bs);
    user_stream_t *user_stream = (user_stream_t*)bs_user_data;

    printf("[bytestream]|bytes_sent:%zu|bytes_rcvd:%zu|recv_fin:%d|snd_times:%d|rcv_times:%d|\n", stats.bytes_sent, stats.bytes_rcvd, user_stream->recv_fin, user_stream->snd_times, user_stream->rcv_times);

    if (user_stream->send_body) {
        free(user_stream->send_body);
    }

    if (user_stream->recv_body) {
        free(user_stream->recv_body);
    }

    free(user_stream);
    return 0;
}

int xqc_h3_ext_bytestream_read_callback(xqc_h3_ext_bytestream_t *h3_ext_bs, 
	const void *data, size_t data_len, uint8_t fin, void *bs_user_data, uint64_t data_recv_time)
{
    user_stream_t *user_stream = (user_stream_t*)bs_user_data;
    int ret = 0, sent = 0;

    user_stream->recv_body_len = 0;
    user_stream->recv_fin = 0;
    user_stream->send_offset = 0;

    if (data_len > 0) {
        memcpy(user_stream->send_body + user_stream->recv_body_len, data, data_len);
        user_stream->recv_body_len += data_len;
    }

    if (!user_stream->recv_fin) {
        user_stream->recv_fin = fin;
    }

    user_stream->rcv_times++;

    printf("[bytestream]|stream_id:%"PRIu64"|data_len:%zu|fin:%d|recv_time:%"PRIu64"|\n", 
           xqc_h3_ext_bytestream_id(h3_ext_bs), data_len, fin, data_recv_time);

    sent = xqc_server_bytestream_send(h3_ext_bs, user_stream);
    if (sent < 0 && sent != -XQC_EAGAIN) {
        //something went wrong
        printf("xqc_server_bytestream_send error: %d\n", ret);
        if (!(sent == -XQC_H3_BYTESTREAM_FIN_SENT && g_test_case == 99)) {
            xqc_h3_ext_bytestream_close(h3_ext_bs);
        }
    }

    return 0;
}

int xqc_h3_ext_bytestream_write_callback(xqc_h3_ext_bytestream_t *h3_ext_bs, 
	void *bs_user_data)
{
    user_stream_t *us = bs_user_data;
    int ret;
    printf("[bytestream]|write callback|\n");
    ret = xqc_server_bytestream_send(h3_ext_bs, us);
    if (ret == -XQC_EAGAIN) {
        ret = 0;
        printf("[bytestream]|write blocked|\n");
    }
    return 0;
}

void
xqc_client_h3_send_pure_fin(int fd, short what, void *arg)
{
    user_stream_t *user_stream = arg;
    xqc_h3_request_finish(user_stream->h3_request);
}



#define MAX_HEADER 100

int
xqc_server_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream)
{
    ssize_t ret = 0;
    int header_cnt = 6;
    xqc_http_header_t header[MAX_HEADER] = {
        {
            .name   = {.iov_base = ":method", .iov_len = 7},
            .value  = {.iov_base = "POST", .iov_len = 4},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = ":scheme", .iov_len = 7},
            .value  = {.iov_base = g_scheme, .iov_len = strlen(g_scheme)},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "host", .iov_len = 4},
            .value  = {.iov_base = g_host, .iov_len = strlen(g_host)},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = ":path", .iov_len = 5},
            .value  = {.iov_base = g_path, .iov_len = strlen(g_path)},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "content-type", .iov_len = 12},
            .value  = {.iov_base = "text/plain", .iov_len = 10},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = ":status", .iov_len = 7},
            .value  = {.iov_base = "200", .iov_len = 3},
            .flags  = 0,
        },
    };

    if (g_test_case == 9) {
        memset(test_long_value, 'a', XQC_TEST_LONG_HEADER_LEN - 1);

        xqc_http_header_t test_long_hdr = {
            .name   = {.iov_base = "long_filed_line", .iov_len = 15},
            .value  = {.iov_base = test_long_value, .iov_len = strlen(test_long_value)},
            .flags  = 0,
        };

        header[header_cnt] = test_long_hdr;
        header_cnt++;
    }

    xqc_http_headers_t headers = {
        .headers = header,
        .count  = header_cnt,
    };

    int header_only = 0;
    int send_fin = 1;

    if (g_echo && user_stream->recv_body_len == 0) {
        header_only = 1;
    }

    if (g_test_case == 100) {
        user_stream->ev_timeout = event_new(eb, -1, 0, xqc_client_h3_send_pure_fin, user_stream);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        event_add(user_stream->ev_timeout, &tv);
        send_fin = 0;
    }

    if (user_stream->header_sent == 0) {
        ret = xqc_h3_request_send_headers(h3_request, &headers, header_only && send_fin);
        if (ret < 0) {
            printf("xqc_h3_request_send_headers error %zd\n", ret);
            return ret;

        } else {
            printf("xqc_h3_request_send_headers success size=%zd\n", ret);
            user_stream->header_sent = 1;
        }

        if (header_only) {
            return 0;
        }
    }

    if (user_stream->send_body == NULL) {
        user_stream->send_body_max = MAX_BUF_SIZE;

        /* priority: echo > specified size > specified file > default size */
        if (g_echo) {
            user_stream->send_body = malloc(user_stream->recv_body_len);
            memcpy(user_stream->send_body, user_stream->recv_body, user_stream->recv_body_len);
            user_stream->send_body_len = user_stream->recv_body_len;

        } else {
            if (g_send_body_size_defined) {
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;

            } else if (g_read_body) {
                user_stream->send_body = malloc(user_stream->send_body_max);
                ret = read_file_data(user_stream->send_body, user_stream->send_body_max, g_read_file);
                if (ret < 0) {
                    printf("read body error\n");
                    return -1;

                } else {
                    user_stream->send_body_len = ret;
                }

            } else {
                if (g_send_body_size_from_cdf == 1) {
                    g_send_body_size = get_random_from_cdf();
                    printf("send_request, size_from_cdf:%d\n", g_send_body_size);
                }
                user_stream->send_body = malloc(g_send_body_size);
                user_stream->send_body_len = g_send_body_size;
            }
        }
    }


    if (user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset,
                                       user_stream->send_body_len - user_stream->send_offset, send_fin);
        if (ret < 0) {
            printf("xqc_h3_request_send_body error %zd\n", ret);
            return 0;

        } else {
            user_stream->send_offset += ret;
            // mpshell
            // printf("xqc_h3_request_send_body sent:%zd, offset=%"PRIu64"\n", ret, user_stream->send_offset);
        }
    }

    if (g_test_case == 12 /* test linger close */
        && user_stream->send_offset == user_stream->send_body_len)
    {
        user_conn_t *user_conn = xqc_h3_get_conn_user_data_by_request(h3_request);
        xqc_h3_conn_close(ctx.engine, &user_conn->cid);
        printf("xqc_h3_conn_close\n");
    }

    return 0;
}

int
xqc_server_request_create_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    int ret = 0;

    user_stream_t *user_stream = calloc(1, sizeof(*user_stream));
    user_stream->h3_request = h3_request;
    xqc_h3_request_set_user_data(h3_request, user_stream);

    if (g_test_case == 99) {
        xqc_h3_request_finish(h3_request);
    }


    if (g_test_case == 14) {
        xqc_h3_request_close(h3_request);
        return -1;
    }


    return 0;
}

int
xqc_server_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    DEBUG;
    user_stream_t *user_stream = (user_stream_t*)user_data;

    if (g_test_case == 100) {
        if (user_stream->ev_timeout) {
            event_free(user_stream->ev_timeout);
        }
    }

    free(user_stream->send_body);
    free(user_stream->recv_body);
    free(user_stream);

    return 0;
}

int
xqc_server_request_write_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    //DEBUG;
    int ret = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    ret = xqc_server_request_send(h3_request, user_stream);
    return ret;
}

int
xqc_server_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data)
{
    //DEBUG;
    int ret;
    unsigned char fin = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;

    if ((flag & XQC_REQ_NOTIFY_READ_HEADER) || (flag & XQC_REQ_NOTIFY_READ_TRAILER)) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }

        for (int i = 0; i < headers->count; i++) {
            printf("%s = %s\n", (char *)headers->headers[i].name.iov_base, (char *)headers->headers[i].value.iov_base);

            if (memcmp((char *)headers->headers[i].name.iov_base, "priority", 8) == 0) {
                xqc_h3_priority_t h3_prio;
                xqc_int_t ret = xqc_parse_http_priority(&h3_prio,
                                                        headers->headers[i].value.iov_base,
                                                        headers->headers[i].value.iov_len);
                if (ret != XQC_OK) {
                    printf("xqc_parse_http_priority error\n");

                } else {
                    ret = xqc_h3_request_set_priority(h3_request, &h3_prio);
                    if (ret != XQC_OK) {
                        printf("xqc_h3_request_set_priority error\n");
                    }
                }
            }
        }

        user_stream->header_recvd++;

        if (fin) {
            /* only header. request received, start processing business logic. */
            xqc_server_request_send(h3_request, user_stream);
            return 0;
        }

        /* continue to receive body */
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {

        if (g_echo && user_stream->recv_body == NULL) {
            user_stream->recv_body = malloc(MAX_BUF_SIZE);
            if (user_stream->recv_body == NULL) {
                printf("recv_body malloc error\n");
                return -1;
            }
        }

        int save = g_save_body;

        if (save && user_stream->recv_body_fp == NULL) {
            user_stream->recv_body_fp = fopen(g_write_file, "wb");
            if (user_stream->recv_body_fp == NULL) {
                printf("open error\n");
                return -1;
            }
        }

        char buff[4096] = {0};
        size_t buff_size = 4096;
        ssize_t read;
        ssize_t read_sum = 0;
        do {
            read = xqc_h3_request_recv_body(h3_request, buff, buff_size, &fin);
            if (read == -XQC_EAGAIN) {
                break;

            } else if (read < 0) {
                printf("xqc_h3_request_recv_body error %zd\n", read);
                return 0;
            }

            read_sum += read;

            /* write received body to file */
            if (save && fwrite(buff, 1, read, user_stream->recv_body_fp) != read) {
                printf("fwrite error\n");
                return -1;
            }

            if (save) {
                fflush(user_stream->recv_body_fp);
            }

            /* write received body to memory */
            if (g_echo) {
                memcpy(user_stream->recv_body + user_stream->recv_body_len, buff, read);
            }
            user_stream->recv_body_len += read;

        } while (read > 0 && !fin);

        // mpshell
        // printf("xqc_h3_request_recv_body read:%zd, offset:%zu, fin:%d\n", read_sum, user_stream->recv_body_len, fin);
    }

    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;

        printf("h3 fin only received\n");
    }

    if (fin) {
        xqc_server_request_send(h3_request, user_stream);
    }

    return 0;
}


ssize_t 
xqc_server_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data; //user_data may be empty when "reset" is sent
    ssize_t res;
    static ssize_t last_snd_sum = 0;
    static ssize_t snd_sum = 0;
    int fd = ctx.fd;

    /* COPY to run corruption test cases */
    unsigned char send_buf[XQC_PACKET_TMP_BUF_LEN];
    size_t send_buf_size = 0;
    
    if (size > XQC_PACKET_TMP_BUF_LEN) {
        printf("xqc_server_write_socket err: size=%zu is too long\n", size);
        return XQC_SOCKET_ERROR;
    }
    send_buf_size = size;
    memcpy(send_buf, buf, send_buf_size);

    /* server Initial dcid corruption ... */
    if (g_test_case == 3) {
        /* client initial dcid corruption, bytes [6, 13] is the DCID of xquic's Initial packet */
        g_test_case = -1;
        send_buf[6] = ~send_buf[6];
    }

    /* server Initial scid corruption ... */
    if (g_test_case == 4) {
        /* bytes [15, 22] is the SCID of xquic's Initial packet */
        g_test_case = -1;
        send_buf[15] = ~send_buf[15];
    }

    /* server odcid hash ... */
    if (g_test_case == 5) {
        /* the first dategram of server is Initial/server hello, drop it */
        g_test_case = -1;
        return size;
    }

    do {
        set_sys_errno(0);
        res = sendto(fd, send_buf, send_buf_size, 0, peer_addr, peer_addrlen);
        // printf("xqc_server_send write %zd, %s\n", res, strerror(get_sys_errno()));
        if (res < 0) {
            printf("xqc_server_write_socket err %zd %s\n", res, strerror(get_sys_errno()));
            if (get_sys_errno() == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }

        } else {
            snd_sum += res;
        }
    } while ((res < 0) && (EINTR== get_sys_errno()));

    if ((xqc_now() - last_snd_ts) > 200000) {
        // mpshell
        // printf("sending rate: %.3f Kbps\n", (snd_sum - last_snd_sum) * 8.0 * 1000 / (xqc_now() - last_snd_ts));
        last_snd_ts = xqc_now();
        last_snd_sum = snd_sum;
    }

    return res;
}

ssize_t
xqc_server_write_socket_ex(uint64_t path_id,
    const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data)
{
    return xqc_server_write_socket(buf, size, peer_addr, peer_addrlen, user_data);
}


ssize_t
xqc_server_stateless_reset(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    const struct sockaddr *local_addr, socklen_t local_addrlen, void *user_data)
{
    return xqc_server_write_socket(buf, size, peer_addr, peer_addrlen, user_data);
}

void
xqc_server_conn_peer_addr_changed_notify(xqc_connection_t *conn, void *conn_user_data)
{
    printf("xqc_server_conn_peer_addr_changed_notify\n");

}

void
xqc_server_path_peer_addr_changed_notify(xqc_connection_t *conn, uint64_t path_id, void *conn_user_data)
{
    printf("xqc_server_path_peer_addr_changed_notify\n");
}

void
xqc_server_path_removed_notify(const xqc_cid_t *scid, uint64_t path_id,
    void *conn_user_data)
{
    user_conn_t *user_conn = (user_conn_t *) conn_user_data;

    if (!g_enable_multipath) {
        return;
    }

    printf("***** path removed. path_id: %" PRIu64 "\n", path_id);
}

void
xqc_server_socket_write_handler(xqc_server_ctx_t *ctx)
{
    DEBUG
}

int g_recv_total = 0;
void
xqc_server_socket_read_handler(xqc_server_ctx_t *ctx)
{
    //DEBUG;
    ssize_t recv_sum = 0;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    ssize_t recv_size = 0;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
    uint64_t recv_time;
    xqc_int_t ret;

#ifdef __linux__
    int batch = 0; /* packets are not necessarily on the same connection */
    if (batch) {
#define VLEN 100
#define BUFSIZE XQC_PACKET_TMP_BUF_LEN
#define TIMEOUT 10
        struct sockaddr_in6 pa[VLEN];
        struct mmsghdr msgs[VLEN];
        struct iovec iovecs[VLEN];
        char bufs[VLEN][BUFSIZE+1];
        struct timespec timeout;
        int retval;

        do {
            memset(msgs, 0, sizeof(msgs));
            for (int i = 0; i < VLEN; i++) {
                iovecs[i].iov_base = bufs[i];
                iovecs[i].iov_len = BUFSIZE;
                msgs[i].msg_hdr.msg_iov = &iovecs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_hdr.msg_name = &pa[i];
                msgs[i].msg_hdr.msg_namelen = peer_addrlen;
            }

            timeout.tv_sec = TIMEOUT;
            timeout.tv_nsec = 0;

            retval = recvmmsg(ctx->fd, msgs, VLEN, 0, &timeout);
            if (retval == -1) {
                break;
            }

            uint64_t recv_time = xqc_now();
            for (int i = 0; i < retval; i++) {
                recv_sum += msgs[i].msg_len;
                if (xqc_engine_packet_process(ctx->engine, iovecs[i].iov_base, msgs[i].msg_len,
                                              (struct sockaddr *) (&ctx->local_addr), ctx->local_addrlen,
                                              (struct sockaddr *) (&pa[i]), peer_addrlen,
                                              (xqc_usec_t)recv_time, NULL) != XQC_OK)                                              
                {
                    printf("xqc_server_read_handler: packet process err\n");
                    return;
                }
            }
        } while (retval > 0);
        goto finish_recv;
    }
#endif

    do {
        recv_size = recvfrom(ctx->fd, packet_buf, sizeof(packet_buf), 0, (struct sockaddr *) &peer_addr,
                             &peer_addrlen);
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("!!!!!!!!!recvfrom: recvmsg = %zd err=%s\n", recv_size, strerror(get_sys_errno()));
            break;
        }

        /* amplification limit */
        if (g_test_case == 8) {
            static int loss_num = 0;
            loss_num++;
            /* continuous loss to make server at amplification limit */
            if (loss_num >= 2 && loss_num <= 10) {
                continue;
            }
        }

        recv_sum += recv_size;

        recv_time = xqc_now();
        //printf("xqc_server_read_handler recv_size=%zd, recv_time=%llu, now=%llu, recv_total=%d\n", recv_size, recv_time, xqc_now(), ++g_recv_total);
        /*printf("peer_ip: %s, peer_port: %d\n", inet_ntoa(ctx->peer_addr.sin_addr), ntohs(ctx->peer_addr.sin_port));
        printf("local_ip: %s, local_port: %d\n", inet_ntoa(ctx->local_addr.sin_addr), ntohs(ctx->local_addr.sin_port));*/

        ret = xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                        (struct sockaddr *) (&ctx->local_addr), ctx->local_addrlen,
                                        (struct sockaddr *) (&peer_addr), peer_addrlen,
                                        (xqc_usec_t) recv_time, NULL);
        if (ret != XQC_OK)
        {
            printf("xqc_server_read_handler: packet process err: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

finish_recv:
    // mpshell
    // printf("recvfrom size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx->engine);
}


static void
xqc_server_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    if (what & EV_WRITE) {
        xqc_server_socket_write_handler(ctx);

    } else if (what & EV_READ) {
        xqc_server_socket_read_handler(ctx);

    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}

int
xqc_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    DEBUG;
    user_conn_t *user_conn = calloc(1, sizeof(*user_conn));
    xqc_conn_set_transport_user_data(conn, user_conn);

    xqc_int_t ret = xqc_conn_get_peer_addr(conn, (struct sockaddr *)&user_conn->peer_addr,
                                           sizeof(user_conn->peer_addr), &user_conn->peer_addrlen);
    if (ret != XQC_OK) {
        return -1;
    }

    printf("-- server_accept user_conn: %p\n", user_conn);

    memcpy(&user_conn->cid, cid, sizeof(*cid));

    if (g_test_case == 11) {
        g_test_case = -1;
        return -1;
    }

    if (g_batch) {
        int ret = connect(ctx.fd, (struct sockaddr *)&user_conn->peer_addr, user_conn->peer_addrlen);
        if (ret != 0) {
            printf("connect error, errno: %d\n", get_sys_errno());
            return ret;
        }
    }

    return 0;
}

void
xqc_server_refuse(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t *)user_data;
    printf("-- server_refuse user_conn: %p\n", user_conn);

    free(user_conn);
    user_conn = NULL;
}

static int
xqc_server_create_socket(const char *addr, unsigned int port)
{
    int fd;
    int type = g_ipv6 ? AF_INET6 : AF_INET;
    ctx.local_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    struct sockaddr *saddr = (struct sockaddr *)&ctx.local_addr;
    int size;
    int optval;

    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", get_sys_errno());
        return -1;
    }

#ifdef XQC_SYS_WINDOWS
    if (ioctlsocket(fd, FIONBIO, &optval) == SOCKET_ERROR) {
		goto err;
	}
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }
#endif

    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    if (type == AF_INET6) {
        memset(saddr, 0, sizeof(struct sockaddr_in6));
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)saddr;
        addr_v6->sin6_family = type;
        addr_v6->sin6_port = htons(port);
        addr_v6->sin6_addr = in6addr_any;

    } else {
        memset(saddr, 0, sizeof(struct sockaddr_in));
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)saddr;
        addr_v4->sin_family = type;
        addr_v4->sin_port = htons(port);
        if (g_spec_local_addr) {
            addr_v4->sin_addr.s_addr = inet_addr(addr);
        } else {
            addr_v4->sin_addr.s_addr = htonl(INADDR_ANY);
        }
    }

    if (bind(fd, saddr, ctx.local_addrlen) < 0) {
        printf("bind socket failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}


static void
xqc_server_engine_callback(int fd, short what, void *arg)
{
    // mpshell
    // printf("timer wakeup now:%"PRIu64"\n", xqc_now());
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

static ssize_t
xqc_server_cid_generate(const xqc_cid_t *ori_cid, uint8_t *cid_buf, size_t cid_buflen, void *engine_user_data)
{
    ssize_t              cid_buf_index = 0, i;
    ssize_t              cid_len, sid_len, nonce_len;
    xqc_quic_lb_ctx_t   *quic_lb_ctx;
    xqc_flag_t           encrypt_cid_on;
    uint8_t              out_buf[XQC_MAX_CID_LEN];
    quic_lb_ctx = &(ctx.quic_lb_ctx);
    cid_len = quic_lb_ctx->cid_len;
    sid_len = quic_lb_ctx->sid_len;
    nonce_len = cid_len - sid_len - XQC_FIRST_OCTET;

    if (sid_len < 0 || sid_len > cid_len || cid_len > cid_buflen) {
        return XQC_ERROR;
    }

    cid_buf[cid_buf_index] = quic_lb_ctx->conf_id;
    cid_buf_index += XQC_FIRST_OCTET;

    memcpy(cid_buf + cid_buf_index, quic_lb_ctx->sid_buf, sid_len);
    cid_buf_index += sid_len;

    for (i = cid_buf_index; i < cid_len; i++) {
        cid_buf[i] = (uint8_t)rand();
    }

    memcpy(out_buf, cid_buf, cid_len);

    encrypt_cid_on = quic_lb_ctx->lb_cid_enc_on;
    if (encrypt_cid_on) {
        int res = xqc_lb_cid_encryption(cid_buf, sid_len + nonce_len, out_buf, XQC_MAX_CID_LEN, quic_lb_ctx->lb_cid_key, XQC_LB_CID_KEY_LEN, ctx.engine);
        if (res != XQC_OK) {
            printf("|xquic|lb-cid encryption error|");
            return -XQC_EENCRYPT_LB_CID;
        }
    }

    memcpy(cid_buf, out_buf, cid_len);

    return cid_len;

}


int 
xqc_server_open_log_file(void *engine_user_data)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    //ctx->log_fd = open("/home/jiuhai.zjh/ramdisk/slog", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    ctx->log_fd = open(g_log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

int 
xqc_server_close_log_file(void *engine_user_data)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return -1;
    }
    close(ctx->log_fd);
    return 0;
}


void 
xqc_server_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN + 1];

    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        printf("xqc_server_write_log fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char *)buf);
    if (log_len < 0) {
        printf("xqc_server_write_log err\n");
        return;
    }

    int write_len = write(ctx->log_fd, log_buf, log_len);
    if (write_len < 0) {
        printf("xqc_server_write_log write failed, errno: %d\n", get_sys_errno());
    }
}

void 
xqc_server_write_qlog(qlog_event_importance_t imp, const void *buf, size_t count, void *engine_user_data)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN + 1];

    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        printf("xqc_server_write_qlog fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char *)buf);
    if (log_len < 0) {
        printf("xqc_server_write_qlog err\n");
        return;
    }

    int write_len = write(ctx->log_fd, log_buf, log_len);
    if (write_len < 0) {
        printf("xqc_server_write_log write failed, errno: %d\n", get_sys_errno());
    }
}


/**
 * key log functions
 */

int
xqc_server_open_keylog_file(xqc_server_ctx_t *ctx)
{
    ctx->keylog_fd = open("./skeys.log", (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    return 0;
}

int
xqc_server_close_keylog_file(xqc_server_ctx_t *ctx)
{
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    close(ctx->keylog_fd);
    ctx->keylog_fd = 0;
    return 0;
}


void
xqc_keylog_cb(const xqc_cid_t *scid, const char *line, void *user_data)
{
    xqc_server_ctx_t *ctx = (xqc_server_ctx_t*)user_data;
    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }
    
    printf("scid:%s\n", xqc_scid_str(ctx->engine, scid));
    int write_len = write(ctx->keylog_fd, line, strlen(line));
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_sys_errno());
        return;
    }

    write_len = write(ctx->keylog_fd, "\n", 1);
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_sys_errno());
    }
}

#if defined(XQC_SUPPORT_SENDMMSG) && !defined(XQC_SYS_WINDOWS)
ssize_t xqc_server_write_mmsg(const struct iovec *msg_iov, unsigned int vlen,
                                const struct sockaddr *peer_addr,
                                socklen_t peer_addrlen, void *user)
{
    const int MAX_SEG = 128;
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res = 0;
    int fd = ctx.fd;
    struct mmsghdr mmsg[MAX_SEG];
    memset(&mmsg, 0, sizeof(mmsg));
    for (int i = 0; i < vlen; i++) {
        mmsg[i].msg_hdr.msg_iov = (struct iovec *)&msg_iov[i];
        mmsg[i].msg_hdr.msg_iovlen = 1;
    }
    do {
        set_sys_errno(0);
        res = sendmmsg(fd, mmsg, vlen, 0);
        if (res < 0) {
            printf("sendmmsg err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (errno == EINTR));
    return res;
}

ssize_t xqc_server_mp_write_mmsg(uint64_t path_id,
    const struct iovec *msg_iov, unsigned int vlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    return xqc_server_write_mmsg(msg_iov, vlen, peer_addr, peer_addrlen, user);
}
#endif

void
stop(int signo)
{
    event_base_loopbreak(eb);
    xqc_engine_destroy(ctx.engine);
    destroy_cdf();
    fflush(stdout);
    exit(0);
}

void usage(int argc, char *argv[]) {
    char *prog = argv[0];
    char *const slash = strrchr(prog, '/');
    if (slash) {
        prog = slash + 1;
    }
    printf(
"Usage: %s [Options]\n"
"\n"
"Options:\n"
"   -a    Server addr.\n"
"   -p    Server port.\n"
"   -e    Echo. Send received body.\n"
"   -c    Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+\n"
"   -C    Pacing on.\n"
"   -L    Endless_sending. default is 0(off).\n"
"   -s    Body size to send.\n"
"   -w    Write received body to file.\n"
"   -r    Read sending body from file. priority e > s > r\n"
"   -l    Log level. e:error d:debug.\n"
"   -u    Url. default https://test.xquic.com/path/resource\n"
"   -x    Test case ID\n"
"   -6    IPv6\n"
"   -b    batch\n"
"   -S    server sid\n"
"   -M    Enable multi-path on.\n"
"   -R    Enable reinjection. Default is 0, no reinjection.\n"
"   -E    load balance id encryption on\n"
"   -K    load balance id encryption key\n"
"   -o    Output log file path, default ./slog\n"
"   -m    Set mpshell on.\n"
"   -y    Multipath backup path standby.\n"
"   -Q    Multipath backup path standby, set backup_mode on(1). default backup_mode is 0(off).\n"
"   -H    Disable h3_ext.\n"
"   -U    Send_datagram 0 (off), 1 (on), 2(on + batch).\n"
, prog);
}



int main(int argc, char *argv[]) {

    signal(SIGINT, stop);
    signal(SIGTERM, stop);

    g_send_body_size = 1024*1024;
    g_send_body_size_defined = 0;
    g_send_body_size_from_cdf = 0;
    cdf_list = NULL;
    cdf_list_size = 0;
    g_save_body = 0;
    g_read_body = 0;
    g_spec_url = 0;
    g_ipv6 = 0;
    g_max_dgram_size = 0;
    g_send_dgram = 0;
    g_copa_ai = 1.0;
    g_copa_delta = 0.05;
    g_enable_h3_ext = 1;
    g_dgram_qos_level = XQC_DATA_QOS_HIGH;
    g_pmtud_on = 0;

    char server_addr[64] = TEST_ADDR;
    int server_port = TEST_PORT;
    char c_cong_ctl = 'b';
    char c_log_level = 'd';
    int c_cong_plus = 0;
    uint8_t c_qlog_disable = 0;
    char c_qlog_importance = 'r';
    int pacing_on = 0;
    strncpy(g_log_path, "./slog", sizeof(g_log_path));

    //ensure the random sequence is the same for every test
    srand(0);

    int long_opt_index;

    const struct option long_opts[] = {
        {"copa_delta", required_argument, &long_opt_index, 1},
        {"copa_ai_unit", required_argument, &long_opt_index, 2},
        {"dgram_qos", required_argument, &long_opt_index, 3},
        {"pmtud", required_argument, &long_opt_index, 4},
        {"qlog_disable", no_argument, &long_opt_index, 5},
        {"qlog_importance", required_argument, &long_opt_index, 6},
        {0, 0, 0, 0}
    };

    int ch = 0;
    while ((ch = getopt_long(argc, argv, "a:p:efc:Cs:w:r:l:u:x:6bS:MR:o:EK:mLQ:U:yH", long_opts, NULL)) != -1) {
        switch (ch) {
        case 'H':
            printf("option disable h3_ext\n");
            g_enable_h3_ext = 0;
            break;
        case 'U':
            printf("option send_datagram 0 (off), 1 (on), 2(on + batch): %s\n", optarg);
            g_send_dgram = atoi(optarg);
            break;
        case 'Q':
            /* max_datagram_frame_size */
            printf("option max_datagram_frame_size: %s\n", optarg);
            g_max_dgram_size = atoi(optarg);
            break;
        case 'a':
            printf("option addr :%s\n", optarg);
            snprintf(server_addr, sizeof(server_addr), optarg);
            g_spec_local_addr = 1;
            break;
        case 'p': /* Server port. */
            printf("option port :%s\n", optarg);
            server_port = atoi(optarg);
            break;
        case 'e': /* Echo. Send received body. */
            printf("option echo :%s\n", "on");
            g_echo = 1;
            break;
        case 'f':
            printf("option fec: on\n");
            g_enable_fec = 1;
            break;
        case 'c': /* Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+ */
            c_cong_ctl = optarg[0];
            if (strncmp("bbr2", optarg, 4) == 0) {
                c_cong_ctl = 'B';
            }
            if (strncmp("bbr2+", optarg, 5) == 0
                || strncmp("bbr+", optarg, 4) == 0)
            {
                c_cong_plus = 1;
            }
            printf("option cong_ctl : %c: %s: plus? %d\n", c_cong_ctl, optarg, c_cong_plus);
            break;
        case 'L':
            printf("option endless_sending: %s\n", "on");
            g_endless_sending = 1;
            break;
        case 'C': /* Pacing on. */
            printf("option pacing :%s\n", "on");
            pacing_on = 1;
            break;
        case 's': /* Body size to send. */
            printf("option send_body_size :%s\n", optarg);
            g_send_body_size = atoi(optarg);
            if (g_send_body_size == 0) {
                if (load_cdf(optarg) != -1) {
                    g_send_body_size_from_cdf = 1;
                } else {
                    printf("the cdf file of send_body_size does not exist: %s\n", optarg);
                    exit(0);
                }
            } else {
                g_send_body_size_defined = 1;
                if (g_send_body_size > MAX_BUF_SIZE) {
                    printf("max send_body_size :%d\n", MAX_BUF_SIZE);
                    exit(0);
                }
            }
            break;
        case 'w': /* Write received body to file. */
            printf("option save body :%s\n", optarg);
            snprintf(g_write_file, sizeof(g_write_file), optarg);
            g_save_body = 1;
            break;
        case 'r': /* Read sending body from file. priority e > s > r */
            printf("option read body :%s\n", optarg);
            snprintf(g_read_file, sizeof(g_read_file), optarg);
            g_read_body = 1;
            break;
        case 'l': /* Log level. e:error d:debug. */
            printf("option log level :%s\n", optarg);
            c_log_level = optarg[0];
            break;
        case 'u': /* Url. default https://test.xquic.com/path/resource */
            printf("option url :%s\n", optarg);
            snprintf(g_url, sizeof(g_url), optarg);
            g_spec_url = 1;
            sscanf(g_url, "%[^://]://%[^/]%[^?]", g_scheme, g_host, g_path);
            break;
        case 'x': /* Test case ID */
            printf("option test case id: %s\n", optarg);
            g_test_case = atoi(optarg);
            break;
        case '6': /* IPv6 */
            printf("option IPv6 :%s\n", "on");
            g_ipv6 = 1;
            break;
        case 'b': /* batch */
            printf("option send batch: on\n");
            g_batch = 1;
            break;
        case 'S': /* set server sid */
            printf("set server sid \n");
            snprintf(g_sid, sizeof(g_sid), optarg);
            g_sid_len = strlen(g_sid);
            break;
        case 'M':
            printf("option enable multi-path: %s\n",  "on");
            g_enable_multipath = 1;
            break;
        case 'R':
            printf("option enable reinjection: %s\n", "on");
            g_enable_reinjection = atoi(optarg);
            break;
        case 'o':
            printf("option log path :%s\n", optarg);
            snprintf(g_log_path, sizeof(g_log_path), optarg);
            break;
        case 'K': /* set lb cid generator's key */
            printf("set lb-cid-generator key \n");
            snprintf(g_lb_cid_enc_key, sizeof(g_lb_cid_enc_key), optarg);
            g_lb_cid_enc_key_len = strlen(g_lb_cid_enc_key);
            break;
        case 'E': /* set lb_cid encryption on */
            printf("set lb-cid encryption on \n");
            g_lb_cid_encryption_on = 1;
            break;
        case 'm':
            printf("option mpshell on\n");
            /* mpshell 限定 */
            g_mpshell = 1;
            break;
        case 'y':
            printf("option multipath backup path standby :%s\n", "on");
            g_mp_backup_mode = 1;
            break;
        /* long options */
        case 0:

            switch (long_opt_index)
            {
            case 1: /* copa_delta */
                g_copa_delta = atof(optarg);
                if (g_copa_delta <= 0 || g_copa_delta > 0.5) {
                    printf("option g_copa_delta must be in (0, 0.5]\n");
                    exit(0);
                } else {
                    printf("option g_copa_delta: %.4lf\n", g_copa_delta);
                }
                break;

            case 2: /* copa_ai_unit */

                g_copa_ai = atof(optarg);
                if (g_copa_ai < 1.0) {
                    printf("option g_copa_ai must be greater than 1.0\n");
                    exit(0);
                } else {
                    printf("option g_copa_ai: %.4lf\n", g_copa_ai);
                }
                break;

            case 3:
                g_dgram_qos_level = atoi(optarg);
                if (g_dgram_qos_level < XQC_DATA_QOS_HIGHEST || g_dgram_qos_level > XQC_DATA_QOS_LOWEST) {
                    printf("invalid qos level!\n");
                    exit(0);
                } else {
                    printf("option g_dgram_qos_level: %d\n", g_dgram_qos_level);
                }
                break;

            case 4:
                g_pmtud_on = atoi(optarg);
                printf("option g_pmtud_on: %d\n", g_pmtud_on);
                break;

            case 5:
                c_qlog_disable = 1;
                printf("option disable qlog\n");
                break;
            
            case 6:
                c_qlog_importance = optarg[0];
                printf("option qlog importance :%s\n", optarg);
                break;

            default:
                break;
            }

            break;


        default:
            printf("other option :%c\n", ch);
            usage(argc, argv);
            exit(0);
        }
    }

    memset(&ctx, 0, sizeof(ctx));

    char g_session_ticket_file[] = "session_ticket.key";

    xqc_server_open_keylog_file(&ctx);
    xqc_server_open_log_file(&ctx);

    xqc_platform_init_env();

    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    char g_session_ticket_key[2048];
    int ticket_key_len  = read_file_data(g_session_ticket_key, sizeof(g_session_ticket_key), g_session_ticket_file);

    if (ticket_key_len < 0) {
        engine_ssl_config.session_ticket_key_data = NULL;
        engine_ssl_config.session_ticket_key_len = 0;

    } else {
        engine_ssl_config.session_ticket_key_data = g_session_ticket_key;
        engine_ssl_config.session_ticket_key_len = ticket_key_len;
    }

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_server_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_server_write_log,
            .xqc_log_write_stat = xqc_server_write_log,
            .xqc_qlog_event_write = xqc_server_write_qlog,
        },
        .keylog_cb = xqc_keylog_cb,

    };

    xqc_transport_callbacks_t tcbs = {
        .server_accept = xqc_server_accept,
        .server_refuse = xqc_server_refuse,
        .write_socket = xqc_server_write_socket,
        .write_socket_ex = xqc_server_write_socket_ex,
        .conn_update_cid_notify = xqc_server_conn_update_cid_notify,
        .stateless_reset = xqc_server_stateless_reset,
        .conn_peer_addr_changed_notify = xqc_server_conn_peer_addr_changed_notify,
        .path_peer_addr_changed_notify = xqc_server_path_peer_addr_changed_notify,
        .path_removed_notify = xqc_server_path_removed_notify,
    };

    xqc_cong_ctrl_callback_t cong_ctrl;
    uint32_t cong_flags = 0;
    if (c_cong_ctl == 'b') {
        cong_ctrl = xqc_bbr_cb;
        cong_flags = XQC_BBR_FLAG_NONE;
#if XQC_BBR_RTTVAR_COMPENSATION_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR_FLAG_RTTVAR_COMPENSATION;
        }
#endif
    }
#ifdef XQC_ENABLE_RENO
    else if (c_cong_ctl == 'r') {
        cong_ctrl = xqc_reno_cb;
    }
#endif
    else if (c_cong_ctl == 'c') {
        cong_ctrl = xqc_cubic_cb;
    }
#ifdef XQC_ENABLE_BBR2
    else if (c_cong_ctl == 'B') {
        cong_ctrl = xqc_bbr2_cb;
#if XQC_BBR2_PLUS_ENABLED
        if (c_cong_plus) {
            cong_flags |= XQC_BBR2_FLAG_RTTVAR_COMPENSATION;
            cong_flags |= XQC_BBR2_FLAG_FAST_CONVERGENCE;
        }
#endif
    }
#endif
#ifdef XQC_ENABLE_UNLIMITED
    else if (c_cong_ctl == 'u') {
        cong_ctrl = xqc_unlimited_cc_cb;

    } 
#endif
#ifdef XQC_ENABLE_COPA
    else if (c_cong_ctl == 'P') {
        cong_ctrl = xqc_copa_cb;

    }
#endif
    else {
        printf("unknown cong_ctrl, option is b, r, c, u\n");
        return -1;
    }
    printf("congestion control flags: %x\n", cong_flags);

    xqc_conn_settings_t conn_settings = {
        .pacing_on  =   pacing_on,
        .cong_ctrl_callback = cong_ctrl,
        .cc_params  =   {
            .customize_on = 1, 
            .init_cwnd = 32, 
            .cc_optimization_flags = cong_flags,
            .copa_delta_ai_unit = g_copa_ai, 
            .copa_delta_base = g_copa_delta,
        },
        .enable_multipath = g_enable_multipath,
        // .multipath_version = g_multipath_version,
        .enable_encode_fec = g_enable_fec,
        .enable_decode_fec = g_enable_fec,
        .spurious_loss_detect_on = 0,
        .max_datagram_frame_size = g_max_dgram_size,
        // .datagram_force_retrans_on = 1,
        .marking_reinjection = 1,
        .close_dgram_redundancy = XQC_RED_NOT_USE,
    };

    if (g_pmtud_on) {
        conn_settings.enable_pmtud = 1;
    }

    if (g_test_case == 6) {
        conn_settings.idle_time_out = 10000;
    }

    /* enable_multipath */
    if (g_enable_multipath) {
        conn_settings.enable_multipath = g_enable_multipath;
    }

    /* enable_reinjection */
    if (g_enable_reinjection == 1) {
        conn_settings.reinj_ctl_callback    = xqc_default_reinj_ctl_cb;
        conn_settings.mp_enable_reinjection = 1;

    } else if (g_enable_reinjection == 2) {
        conn_settings.reinj_ctl_callback    = xqc_deadline_reinj_ctl_cb;
        conn_settings.mp_enable_reinjection = 2;

    } else if (g_enable_reinjection == 3) {
        conn_settings.reinj_ctl_callback    = xqc_dgram_reinj_ctl_cb;
        conn_settings.mp_enable_reinjection = 4;
        conn_settings.scheduler_callback    = xqc_rap_scheduler_cb;
    }

    if (g_mp_backup_mode) {
        conn_settings.scheduler_callback = xqc_backup_scheduler_cb;
    }

    if (g_enable_fec) {
        xqc_fec_params_t fec_params;
        xqc_fec_schemes_e fec_schemes[XQC_FEC_MAX_SCHEME_NUM] = {XQC_XOR_CODE, XQC_REED_SOLOMON_CODE};
        for (xqc_int_t i = 0; i < XQC_FEC_MAX_SCHEME_NUM; i++) {
            fec_params.fec_encoder_schemes[i] = fec_schemes[i];
            fec_params.fec_decoder_schemes[i] = fec_schemes[i];
        }
        fec_params.fec_encoder_schemes_num = 2;
        fec_params.fec_decoder_schemes_num = 2;
        fec_params.fec_max_window_size = 8;
        conn_settings.fec_params = fec_params;
    }

    if (g_test_case == 12) {
        conn_settings.linger.linger_on = 1;
    }

    /* test reset, destroy connection as soon as possible */
    if (g_test_case == 13) {
        conn_settings.idle_time_out = 1000;
    }

    if (g_test_case == 201) {
        conn_settings.max_pkt_out_size = 1216;
    }

    if (g_test_case == 208) {
        conn_settings.datagram_redundancy = 1;
    }

    if (g_test_case == 209) {
        conn_settings.datagram_redundant_probe = 30000;
    }

    if (g_test_case == 210) {
        conn_settings.datagram_redundancy = 2;
    }

    if (g_test_case == 211) {
        conn_settings.datagram_redundancy = 2;
        conn_settings.datagram_redundant_probe = 30000;
    }

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        return -1;
    }

    config.enable_h3_ext = g_enable_h3_ext;

    switch(c_log_level) {
        case 'e': config.cfg_log_level = XQC_LOG_ERROR; break;
        case 'i': config.cfg_log_level = XQC_LOG_INFO; break;
        case 'w': config.cfg_log_level = XQC_LOG_WARN; break;
        case 's': config.cfg_log_level = XQC_LOG_STATS; break;
        case 'd': config.cfg_log_level = XQC_LOG_DEBUG; break;
        default: config.cfg_log_level = XQC_LOG_DEBUG;
    }

    if (c_qlog_disable) {
        config.cfg_log_event = 0;
    }
    switch(c_qlog_importance) {
        case 's': config.cfg_qlog_importance = EVENT_IMPORTANCE_SELECTED; break;
        case 'c': config.cfg_qlog_importance = EVENT_IMPORTANCE_CORE; break;
        case 'b': config.cfg_qlog_importance = EVENT_IMPORTANCE_BASE; break;
        case 'e': config.cfg_qlog_importance = EVENT_IMPORTANCE_EXTRA; break;
        case 'r': config.cfg_qlog_importance = EVENT_IMPORTANCE_REMOVED; break;
        default: config.cfg_qlog_importance = EVENT_IMPORTANCE_EXTRA;
    }

    eb = event_base_new();
    ctx.ev_engine = event_new(eb, -1, 0, xqc_server_engine_callback, &ctx);

#if defined(XQC_SUPPORT_SENDMMSG) && !defined(XQC_SYS_WINDOWS)
    if (g_batch) {
        tcbs.write_mmsg = xqc_server_write_mmsg,
        tcbs.write_mmsg_ex = xqc_server_mp_write_mmsg;
        config.sendmmsg_on = 1;
    }
#endif

    /* test server cid negotiate */
    if (g_test_case == 1 || g_test_case == 5 || g_test_case == 6 || g_sid_len != 0) {

        if (g_lb_cid_enc_key_len == 0) {
            int i = 0;
            for (i = 0; i < XQC_LB_CID_KEY_LEN; i++) {
                g_lb_cid_enc_key[i] = (uint8_t)rand();
            }

        }

        callback.cid_generate_cb = xqc_server_cid_generate;
        config.cid_negotiate = 1;
        config.cid_len = XQC_MAX_CID_LEN;
    }

    ctx.engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &engine_ssl_config,
                                   &callback, &tcbs, &ctx);
    if (ctx.engine == NULL) {
        printf("error create engine\n");
        return -1;
    }

    xqc_server_set_conn_settings(ctx.engine, &conn_settings);

    /* register http3 callbacks */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = xqc_server_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_server_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_server_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_write_notify = xqc_server_request_write_notify,
            .h3_request_read_notify = xqc_server_request_read_notify,
            .h3_request_create_notify = xqc_server_request_create_notify,
            .h3_request_close_notify = xqc_server_request_close_notify,
        },
        .h3_ext_dgram_cbs = {
            .dgram_read_notify = xqc_server_h3_ext_datagram_read_callback,
            .dgram_write_notify = xqc_server_h3_ext_datagram_write_callback,
            .dgram_acked_notify = xqc_server_h3_ext_datagram_acked_callback,
            .dgram_lost_notify = xqc_server_h3_ext_datagram_lost_callback,
            .dgram_mss_updated_notify = xqc_server_h3_ext_datagram_mss_updated_callback,
        },
        .h3_ext_bs_cbs = {
            .bs_read_notify = xqc_h3_ext_bytestream_read_callback,
            .bs_write_notify = xqc_h3_ext_bytestream_write_callback,
            .bs_create_notify = xqc_h3_ext_bytestream_create_callback,
            .bs_close_notify = xqc_h3_ext_bytestream_close_callback,
        },
    };

    /* register transport callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = xqc_server_conn_create_notify,
            .conn_close_notify = xqc_server_conn_close_notify,
            .conn_handshake_finished = xqc_server_conn_handshake_finished,
        },
        .stream_cbs = {
            .stream_write_notify = xqc_server_stream_write_notify,
            .stream_read_notify = xqc_server_stream_read_notify,
            .stream_create_notify = xqc_server_stream_create_notify,
            .stream_close_notify = xqc_server_stream_close_notify,
        },
        .dgram_cbs = {
            .datagram_acked_notify = xqc_server_datagram_acked_callback,
            .datagram_lost_notify = xqc_server_datagram_lost_callback,
            .datagram_read_notify = xqc_server_datagram_read_callback,
            .datagram_write_notify = xqc_server_datagram_write_callback,
            .datagram_mss_updated_notify = xqc_server_datagram_mss_updated_callback,
        },
    };


    /* test NULL stream callback */
    if (g_test_case == 2) {
        memset(&ap_cbs.stream_cbs, 0, sizeof(ap_cbs.stream_cbs));
    }

    /* init http3 context */
    xqc_int_t ret = xqc_h3_ctx_init(ctx.engine, &h3_cbs);
    if (ret != XQC_OK) {
        printf("init h3 context error, ret: %d\n", ret);
        return ret;
    }

        /* modify h3 default settings */
    if (g_test_case == 150 || g_test_case == 152) {
        xqc_h3_engine_set_dec_max_dtable_capacity(ctx.engine, 4096);
        xqc_h3_engine_set_enc_max_dtable_capacity(ctx.engine, 4096);
        xqc_h3_engine_set_max_field_section_size(ctx.engine, 512);
        xqc_h3_engine_set_qpack_blocked_streams(ctx.engine, 32);
#ifdef XQC_COMPAT_DUPLICATE
        xqc_h3_engine_set_qpack_compat_duplicate(ctx.engine, 1);
#endif
    }

    if (g_test_case == 151 || g_test_case == 153) {
        xqc_h3_engine_set_max_dtable_capacity(ctx.engine, 4096);
        xqc_h3_engine_set_max_field_section_size(ctx.engine, 512);
        xqc_h3_engine_set_qpack_blocked_streams(ctx.engine, 32);
#ifdef XQC_COMPAT_DUPLICATE
        xqc_h3_engine_set_qpack_compat_duplicate(ctx.engine, 1);
#endif
    }

    xqc_engine_register_alpn(ctx.engine, XQC_ALPN_TRANSPORT, 9, &ap_cbs, NULL);

    if (g_test_case == 10) {
        xqc_h3_engine_set_max_field_section_size(ctx.engine, 10000000);
    }

    /* for lb cid generate */
    memcpy(ctx.quic_lb_ctx.sid_buf, g_sid, g_sid_len);
    memcpy(ctx.quic_lb_ctx.lb_cid_key, g_lb_cid_enc_key, XQC_LB_CID_KEY_LEN);
    ctx.quic_lb_ctx.lb_cid_enc_on = g_lb_cid_encryption_on;
    ctx.quic_lb_ctx.sid_len = g_sid_len;
    ctx.quic_lb_ctx.conf_id = 0;
    ctx.quic_lb_ctx.cid_len = XQC_MAX_CID_LEN;

    ctx.fd = xqc_server_create_socket(server_addr, server_port);
    if (ctx.fd < 0) {
        printf("xqc_create_socket error\n");
        return 0;
    }

    ctx.ev_socket = event_new(eb, ctx.fd, EV_READ | EV_PERSIST, xqc_server_socket_event_callback, &ctx);

    event_add(ctx.ev_socket, NULL);
    last_snd_ts = 0;
    event_base_dispatch(eb);

    xqc_h3_ctx_destroy(ctx.engine);
    xqc_engine_destroy(ctx.engine);
    xqc_server_close_keylog_file(&ctx);
    xqc_server_close_log_file(&ctx);
    destroy_cdf();

    return 0;
}
