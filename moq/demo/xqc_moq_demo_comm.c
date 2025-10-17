
#include "xqc_moq_demo_comm.h"

// #define TEST_DROP (g_drop_rate != 0 && (rand() % 1000 < g_drop_rate || g_loss_cnt++ == 0))

#define TEST_DROP (g_drop_rate != 0 && ((g_loss_cnt++) % g_drop_rate == 0))

int g_drop_rate = 0;
int g_loss_cnt = 0;

void
xqc_app_set_log_level(char c_log_level, xqc_config_t *config)
{
    switch(c_log_level) {
        case 'e': config->cfg_log_level = XQC_LOG_ERROR; break;
        case 'i': config->cfg_log_level = XQC_LOG_INFO; break;
        case 'w': config->cfg_log_level = XQC_LOG_WARN; break;
        case 's': config->cfg_log_level = XQC_LOG_STATS; break;
        case 'd': config->cfg_log_level = XQC_LOG_DEBUG; break;
        default: config->cfg_log_level = XQC_LOG_DEBUG;
    }
}


int
xqc_app_read_file_data(unsigned char * data, size_t data_len, char *filename)
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
xqc_app_delete_file(const char *filename)
{
    if (filename == NULL) {
        return -1;
    }
    
    if (remove(filename) != 0) {
        printf("xqc_app_delete_file err\n");
        return -1;
    }

    return 0;
}

void
xqc_app_engine_callback(int fd, short what, void *arg)
{
    // printf("timer wakeup now:%"PRIu64"\n", xqc_now());
    xqc_app_ctx_t *ctx = (xqc_app_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

void
xqc_app_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    xqc_app_ctx_t *ctx = (xqc_app_ctx_t *) user_data;

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);

}

int
xqc_app_open_log_file(void *engine_user_data, const char *file_name)
{
    xqc_app_ctx_t *ctx = (xqc_app_ctx_t*)engine_user_data;
    ctx->log_fd = open(file_name, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

#define XQC_MAX_LOG_LEN 2048
void
xqc_app_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN + 1];

    xqc_app_ctx_t *ctx = (xqc_app_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        printf("xqc_app_write_log fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char *)buf);
    if (log_len < 0) {
        printf("xqc_app_write_log err\n");
        return;
    }

    int write_len = write(ctx->log_fd, log_buf, log_len);
    if (write_len < 0) {
        printf("xqc_app_write_log write failed, errno: %d\n", get_sys_errno());
    }
}

#define XQC_PACKET_TMP_BUF_LEN 1500
ssize_t
xqc_app_write_socket(const unsigned char *buf, size_t size,
                        const struct sockaddr *peer_addr,
                        socklen_t peer_addrlen, void *user_data)
{
    //user_data may be empty when "reset" is sent
    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    user_conn_t *user_conn = (user_conn_t *)user_session->data;
    ssize_t res;
    int fd = user_conn->fd;

    do {
        set_sys_errno(0);

        if (TEST_DROP) {
            return size;
        }

        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xqc_app_write_socket fd:%d err %zd %s\n", fd, res, strerror(get_sys_errno()));
            if (get_sys_errno() == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (EINTR== get_sys_errno()));

    return res;
}

ssize_t
xqc_app_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size, 
                        const struct sockaddr *peer_addr,
                        socklen_t peer_addrlen, void *user_data)
{
    return xqc_app_write_socket(buf, size, peer_addr, peer_addrlen, user_data);
}