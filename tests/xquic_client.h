// tests/xquic_client.h

#ifndef XQUIC_CLIENT_H
#define XQUIC_CLIENT_H

#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "user_conn.h"
#include <string>

class XquicClient {
public:
    XquicClient();
    ~XquicClient();

    // Initialization and Running
    int init(int argc, char *argv[]);
    void run();
    int start(int argc, char *argv[]);

    // Event Handlers
    void on_engine_timer();
    void on_socket_event(int fd, short what);
    void process_socket_read();

    // Callback Implementations
    void on_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);
    void on_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);
    void on_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data);
    void on_conn_ping_acked(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data, void *conn_proto_data);
    void on_conn_update_cid(xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data);
    
    // H3 Callbacks
    void on_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    void on_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
    void on_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data);
    void on_h3_conn_ping_acked(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data);
    void on_h3_conn_update_cid(xqc_h3_conn_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data);
    
    // Stream/Request Callbacks
    xqc_int_t on_stream_write_notify(xqc_stream_t *stream, void *user_data);
    xqc_int_t on_stream_read_notify(xqc_stream_t *stream, void *user_data);
    xqc_int_t on_stream_close_notify(xqc_stream_t *stream, void *user_data);

    xqc_int_t on_request_write_notify(xqc_h3_request_t *req, void *user_data);
    xqc_int_t on_request_read_notify(xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data);
    xqc_int_t on_request_close_notify(xqc_h3_request_t *req, void *user_data);

    // Helpers
    void send_stream_data(xqc_stream_t *stream, user_stream_t *user_stream);
    void send_request(user_conn_t *u_conn);
    void set_event_timer(xqc_msec_t wake_after);
    ssize_t write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr, socklen_t peer_addrlen, user_conn_t *user_conn);

private:
    xqc_engine_t *engine_;
    event_base *event_base_;
    event *ev_engine_;
    
    // Configuration
    std::string server_ip_;
    int port_;
    int transport_only_;
    std::string log_path_;
    
    // Test specific
    size_t send_body_size_;
    int echo_check_;
    int save_file_;
    std::string write_file_;
};

#endif // XQUIC_CLIENT_H