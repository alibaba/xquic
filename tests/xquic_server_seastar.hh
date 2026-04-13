#pragma once

#include "user_conn.h"
#include "xquic_seastar_integration.hh"

#include <seastar/core/future.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/timer.hh>
#include <seastar/net/api.hh>
#include <xquic/xqc_http3.h>
#include <xquic/xquic.h>
#include <cstdint>
#include <optional>
#include <string>

class XquicSeastarServer {
public:
    XquicSeastarServer();
    ~XquicSeastarServer();

    seastar::future<> start(uint16_t port, const std::string& cert_path, const std::string& key_path);
    seastar::future<> stop();

private:
    std::optional<seastar::net::udp_channel> _udp_channel;
    std::optional<seastar::future<>> _receive_loop;
    seastar::gate _background_ops;
    seastar::timer<> _engine_timer;
    xqc_engine_t* _engine;
    XquicSeastarSendIntegration _send_integration;
    user_conn_t _packet_user_conn;
    std::string _cert_path;
    std::string _key_path;
    uint16_t _port;
    bool _stopping;
    bool _send_flush_in_progress;

    void init_xquic_engine();
    seastar::future<> run_receive_loop();
    void on_datagram(seastar::net::udp_datagram& datagram);
    void on_engine_timer_expire();
    ssize_t enqueue_send(const unsigned char *buf, size_t size,
                         const struct sockaddr *peer_addr, socklen_t peer_addrlen);
    void schedule_send_flush();
    seastar::future<> flush_send_queue();
    void send_h3_response(user_stream_t *user_stream);

    int on_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    int on_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    xqc_int_t on_h3_request_write_notify(xqc_h3_request_t *req, void *user_data);
    xqc_int_t on_h3_request_read_notify(xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data);
    xqc_int_t on_h3_request_close_notify(xqc_h3_request_t *req, void *user_data);

    static void ss_set_event_timer(xqc_msec_t wake_after, void *user_data);
    static ssize_t ss_write_socket(const unsigned char *buf, size_t size,
                                   const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                                   void *user_conn);
    static int ss_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    static int ss_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    static xqc_int_t ss_h3_request_write_notify(xqc_h3_request_t *req, void *user_data);
    static xqc_int_t ss_h3_request_read_notify(xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data);
    static xqc_int_t ss_h3_request_close_notify(xqc_h3_request_t *req, void *user_data);
};
