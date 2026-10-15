/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_COMPLEX_CASE_COMMON_H
#define XQC_COMPLEX_CASE_COMMON_H

#include <sys/socket.h>

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>


typedef struct {
    int  fd;
} xqc_complex_case_socket_ctx_t;


/* Must be the first member of a complex test-specific engine context. */
typedef struct {
    xqc_complex_case_socket_ctx_t  socket;
    xqc_engine_t                  *engine;
    struct sockaddr_storage        local;
    socklen_t                      locallen;
    xqc_cid_t                      cid;
    void                          *user_data;
    int                            alive;
} xqc_complex_case_engine_t;


xqc_usec_t xqc_complex_case_now_us(void);

void xqc_complex_case_set_event_timer(xqc_usec_t wake_after,
    void *engine_user_data);

void xqc_complex_case_init_engine_callbacks(
    xqc_engine_callback_t *engine_cbs);

void xqc_complex_case_init_transport_callbacks(
    xqc_transport_callbacks_t *transport_cbs);

ssize_t xqc_complex_case_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data);

ssize_t xqc_complex_case_write_socket_ex(uint64_t path_id,
    const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data);

void xqc_complex_case_save_token(const unsigned char *token,
    unsigned token_len, void *user_data);

void xqc_complex_case_save_session(const char *data, size_t data_len,
    void *user_data);

void xqc_complex_case_save_tp(const char *data, size_t data_len,
    void *user_data);

int xqc_complex_case_cert_verify(const unsigned char **certs,
    const size_t *cert_len, size_t certs_len, void *conn_user_data);

int xqc_complex_case_make_socket(xqc_complex_case_engine_t *ctx,
    const struct sockaddr *bind_addr, socklen_t bind_addrlen);

void xqc_complex_case_pump(xqc_complex_case_engine_t **engines,
    size_t engine_count, int ms);

void xqc_complex_case_engine_release(xqc_complex_case_engine_t *ctx);


#endif
