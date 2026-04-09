// tests/xquic_server.h

#ifndef XQUIC_SERVER_H
#define XQUIC_SERVER_H

#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "user_conn.h"
#include <string>

class XquicServer {
public:
    XquicServer();
    ~XquicServer();

    int start(int argc, char *argv[]);
    int init(int argc, char *argv[]);
    void run();

    // Event Handlers
    void on_engine_timer();
    void on_socket_event(int fd, short what);
    void process_socket_read();

    // Callback Implementations
    void on_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);
    void on_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);
    
    // H3 Callbacks
    void on_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    void on_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    
    // Stream/Request Callbacks
    xqc_int_t on_stream_write_notify(xqc_stream_t *stream, void *user_data);
    xqc_int_t on_stream_read_notify(xqc_stream_t *stream, void *user_data);
    xqc_int_t on_stream_close_notify(xqc_stream_t *stream, void *user_data);

    xqc_int_t on_request_write_notify(xqc_h3_request_t *req, void *user_data);
    xqc_int_t on_request_read_notify(xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data);
    xqc_int_t on_request_close_notify(xqc_h3_request_t *req, void *user_data);

    // Helpers
    void send_response(user_stream_t *user_stream);
    void send_h3_response(user_stream_t *user_stream);
    void set_event_timer(xqc_msec_t wake_after);
    ssize_t write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr, socklen_t peer_addrlen, user_conn_t *user_conn);
    int create_socket(int port, int ipv6);

private:
    xqc_engine_t *engine_;
    event_base *event_base_;
    event *ev_engine_;
    int listen_fd_;
    event *ev_listen_;
    
    // Configuration
    int port_;
    int ipv6_;
    int transport_only_;
    int cc_algo_;
    std::string cert_path_;
    std::string key_path_;
    std::string log_path_;
};

#endif // XQUIC_SERVER_H