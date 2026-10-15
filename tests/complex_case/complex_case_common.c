/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "complex_case_common.h"


xqc_usec_t
xqc_complex_case_now_us(void)
{
    struct timeval  tv;

    gettimeofday(&tv, NULL);
    return (xqc_usec_t) tv.tv_sec * 1000000 + tv.tv_usec;
}


void
xqc_complex_case_set_event_timer(xqc_usec_t wake_after,
    void *engine_user_data)
{
    (void) wake_after;
    (void) engine_user_data;
}


void
xqc_complex_case_init_engine_callbacks(xqc_engine_callback_t *engine_cbs)
{
    memset(engine_cbs, 0, sizeof(*engine_cbs));
    engine_cbs->set_event_timer = xqc_complex_case_set_event_timer;
}


void
xqc_complex_case_init_transport_callbacks(
    xqc_transport_callbacks_t *transport_cbs)
{
    memset(transport_cbs, 0, sizeof(*transport_cbs));
    transport_cbs->write_socket = xqc_complex_case_write_socket;
    transport_cbs->write_socket_ex = xqc_complex_case_write_socket_ex;
    transport_cbs->save_token = xqc_complex_case_save_token;
    transport_cbs->save_session_cb = xqc_complex_case_save_session;
    transport_cbs->save_tp_cb = xqc_complex_case_save_tp;
    transport_cbs->cert_verify_cb = xqc_complex_case_cert_verify;
}


ssize_t
xqc_complex_case_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data)
{
    xqc_complex_case_socket_ctx_t  *ctx;
    ssize_t                         n;

    ctx = conn_user_data;
    if (ctx == NULL || ctx->fd < 0) {
        return XQC_SOCKET_ERROR;
    }

    do {
        errno = 0;
        n = sendto(ctx->fd, buf, size, 0, peer_addr, peer_addrlen);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        return errno == EAGAIN ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
    }

    return n;
}


ssize_t
xqc_complex_case_write_socket_ex(uint64_t path_id,
    const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    (void) path_id;
    return xqc_complex_case_write_socket(buf, size, peer_addr, peer_addrlen,
                                         conn_user_data);
}


void
xqc_complex_case_save_token(const unsigned char *token, unsigned token_len,
    void *user_data)
{
    (void) token;
    (void) token_len;
    (void) user_data;
}


void
xqc_complex_case_save_session(const char *data, size_t data_len,
    void *user_data)
{
    (void) data;
    (void) data_len;
    (void) user_data;
}


void
xqc_complex_case_save_tp(const char *data, size_t data_len, void *user_data)
{
    (void) data;
    (void) data_len;
    (void) user_data;
}


int
xqc_complex_case_cert_verify(const unsigned char **certs,
    const size_t *cert_len, size_t certs_len, void *conn_user_data)
{
    (void) certs;
    (void) cert_len;
    (void) certs_len;
    (void) conn_user_data;
    return 0;
}


int
xqc_complex_case_make_socket(xqc_complex_case_engine_t *ctx,
    const struct sockaddr *bind_addr, socklen_t bind_addrlen)
{
    int  fd;
    int  flags;

    fd = socket(bind_addr->sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    if (bind(fd, bind_addr, bind_addrlen) < 0) {
        close(fd);
        return -1;
    }

    ctx->locallen = sizeof(ctx->local);
    if (getsockname(fd, (struct sockaddr *) &ctx->local, &ctx->locallen) < 0) {
        close(fd);
        return -1;
    }

    ctx->socket.fd = fd;
    return 0;
}


void
xqc_complex_case_pump(xqc_complex_case_engine_t **engines,
    size_t engine_count, int ms)
{
    xqc_usec_t      deadline;
    unsigned char   buf[65536];
    size_t          i;

    deadline = xqc_complex_case_now_us() + (xqc_usec_t) ms * 1000;
    while (xqc_complex_case_now_us() < deadline) {
        struct pollfd  pollfds[engine_count];
        size_t         poll_count = 0;

        for (i = 0; i < engine_count; i++) {
            if (engines[i]->engine == NULL) {
                continue;
            }
            pollfds[poll_count].fd = engines[i]->socket.fd;
            pollfds[poll_count].events = POLLIN;
            pollfds[poll_count].revents = 0;
            poll_count++;
        }

        poll(pollfds, poll_count, 2);

        for (i = 0; i < engine_count; i++) {
            xqc_complex_case_engine_t  *ctx = engines[i];

            if (ctx->engine == NULL) {
                continue;
            }

            for (;;) {
                struct sockaddr_storage  from;
                socklen_t                fromlen = sizeof(from);
                ssize_t                  received;

                received = recvfrom(ctx->socket.fd, buf, sizeof(buf), 0,
                                    (struct sockaddr *) &from, &fromlen);
                if (received <= 0) {
                    break;
                }

                xqc_engine_packet_process(ctx->engine, buf, (size_t) received,
                                          (struct sockaddr *) &ctx->local,
                                          ctx->locallen,
                                          (struct sockaddr *) &from, fromlen,
                                          xqc_complex_case_now_us(),
                                          ctx->user_data);
            }

            xqc_engine_finish_recv(ctx->engine);
            xqc_engine_main_logic(ctx->engine);
        }
    }
}


void
xqc_complex_case_engine_release(xqc_complex_case_engine_t *ctx)
{
    if (ctx->engine != NULL) {
        xqc_engine_destroy(ctx->engine);
        ctx->engine = NULL;
    }

    if (ctx->socket.fd >= 0) {
        close(ctx->socket.fd);
        ctx->socket.fd = -1;
    }

    ctx->alive = 0;
}
