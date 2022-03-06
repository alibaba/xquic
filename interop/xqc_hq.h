/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_HQ_H
#define XQC_HQ_H

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_errno.h>


typedef struct xqc_hq_conn_s    xqc_hq_conn_t;
typedef struct xqc_hq_request_s xqc_hq_request_t;


typedef int (*xqc_hq_conn_notify_pt)(xqc_hq_conn_t *conn, const xqc_cid_t *cid,
    void *conn_user_data);


/**
 * @brief application-layer-protocol callback funcitons for hq
 */
typedef struct xqc_hq_conn_callbacks_s {

    /**
     * connection create notify callback. REQUIRED for server, OPTIONAL for client.
     */
    xqc_hq_conn_notify_pt               conn_create_notify;

    /**
     * connection close notify. REQUIRED for both client and server
     */
    xqc_hq_conn_notify_pt               conn_close_notify;

} xqc_hq_conn_callbacks_t;


typedef int (*xqc_hq_req_create_notify_pt)(xqc_hq_request_t *hq_req, void *req_user_data);

typedef int (*xqc_hq_req_close_notify_pt)(xqc_hq_request_t *hq_req, void *req_user_data);

typedef int (*xqc_hq_req_read_notify_pt)(xqc_hq_request_t *hq_req, void *req_user_data);

typedef int (*xqc_hq_req_write_notify_pt)(xqc_hq_request_t *hq_req, void *req_user_data);

typedef struct xqc_hq_request_callbacks_s {
    /**
     * stream create callback function. REQUIRED for server, OPTIONAL for client.
     */
    xqc_hq_req_create_notify_pt         req_create_notify;

    /**
     * stream close callback function. REQUIRED for both server and client.
     */
    xqc_hq_req_close_notify_pt          req_close_notify;

    /**
     * hq request read callback function. REQUIRED for both client and server
     */
    xqc_hq_req_read_notify_pt           req_read_notify;

    /**
     * stream write callback function. REQUIRED for both client and server
     */
    xqc_hq_req_write_notify_pt          req_write_notify;

} xqc_hq_request_callbacks_t;


/**
 * @brief hq callbacks
 */
typedef struct xqc_hq_callbacks_s {

    /* hq connection callbacks */
    xqc_hq_conn_callbacks_t     hqc_cbs;

    /* hq request callbacks */
    xqc_hq_request_callbacks_t  hqr_cbs;

} xqc_hq_callbacks_t;



/**
 * @brief init the environment of hq, MUST be invoked before create hq connection
 */
xqc_int_t
xqc_hq_ctx_init(xqc_engine_t *engine, xqc_hq_callbacks_t *hq_cbs);


xqc_int_t
xqc_hq_ctx_destroy(xqc_engine_t *engine);


/**
 * @brief hq connection functions
 */

xqc_hq_conn_t *
xqc_hq_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings, 
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data);

xqc_int_t
xqc_hq_conn_close(xqc_engine_t *engine, xqc_hq_conn_t *hqc, const xqc_cid_t *cid);

void
xqc_hq_conn_set_user_data(xqc_hq_conn_t *hqc, void *user_data);

xqc_int_t
xqc_hq_conn_get_peer_addr(xqc_hq_conn_t *hqc, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *peer_addr_len);


/**
 * @brief hq request functions
 */

xqc_hq_request_t *
xqc_hq_request_create(xqc_engine_t *engine, xqc_hq_conn_t *hqc, const xqc_cid_t *cid,
    void *user_data);

void
xqc_hq_request_destroy(xqc_hq_request_t * hqr);

void xqc_hq_request_set_user_data(xqc_hq_request_t *hqr, void *user_data);

ssize_t
xqc_hq_request_send_req(xqc_hq_request_t *hqr, const char *resource);

ssize_t
xqc_hq_request_recv_req(xqc_hq_request_t *hqr, char *res_buf, size_t buf_sz, uint8_t *fin);

ssize_t
xqc_hq_request_send_rsp(xqc_hq_request_t *hqr, const uint8_t *res_buf, size_t res_buf_len,
    uint8_t fin);

ssize_t
xqc_hq_request_recv_rsp(xqc_hq_request_t *hqr, char *res_buf, size_t buf_sz, uint8_t *fin);

xqc_int_t
xqc_hq_request_close(xqc_hq_request_t *hqr);


#endif
