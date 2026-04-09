// xquic_server.cpp
#include "xquic_server.h"
#include "user_conn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event2/event.h>
#include <time.h>

// Helper to get current time in microseconds
static uint64_t xqc_now() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

// Trampolines
extern "C" {
    void xqc_server_engine_trampoline(int fd, short what, void *arg) {
        if (arg) static_cast<XquicServer*>(arg)->on_engine_timer();
    }

    void xqc_server_socket_trampoline(int fd, short what, void *arg) {
        if (arg) static_cast<XquicServer*>(arg)->on_socket_event(fd, what);
    }

    void xqc_server_set_event_timer_tramp(xqc_msec_t wake_after, void *user_data) {
        if (user_data) static_cast<XquicServer*>(user_data)->set_event_timer(wake_after);
    }

    ssize_t xqc_server_write_socket_tramp(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_conn) {
        if (user_conn) {
            user_conn_t *u_conn = (user_conn_t *)user_conn;
            if (u_conn && u_conn->server) {
                return ((XquicServer*)u_conn->server)->write_socket(buf, size, peer_addr, peer_addrlen, u_conn);
            }
        }
        return -1;
    }
    
    void xqc_server_keylog_tramp(const xqc_cid_t *scid, const char *line, void *user_data) {
        (void)scid;
        (void)line;
        (void)user_data;
    }

    int xqc_server_accept_tramp(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data) {
        return 0;
    }

    void xqc_server_refuse_tramp(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data) {
    }

    ssize_t xqc_server_stateless_reset_tramp(const unsigned char *buf, size_t size,
        const struct sockaddr *peer_addr, socklen_t peer_addrlen,
        const struct sockaddr *local_addr, socklen_t local_addrlen,
        void *user_data) {
        return -1;
    }

    void xqc_server_conn_update_cid_notify_tramp(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
        const xqc_cid_t *new_cid, void *conn_user_data) {
    }

    void xqc_server_save_token_tramp(const unsigned char *token, uint32_t token_len, void *conn_user_data) {
    }

    void xqc_server_save_session_tramp(const char *data, size_t data_len, void *conn_user_data) {
    }

    void xqc_server_save_tp_tramp(const char *data, size_t data_len, void *conn_user_data) {
    }

    int xqc_server_cert_verify_tramp(const unsigned char *certs[], const size_t cert_len[],
        size_t certs_len, void *conn_user_data) {
        return 0;
    }

    void xqc_server_ready_to_create_path_notify_tramp(const xqc_cid_t *scid, void *conn_user_data) {
    }

    int xqc_server_path_created_notify_tramp(xqc_connection_t *conn,
        const xqc_cid_t *scid, uint64_t path_id, void *conn_user_data) {
        return 0;
    }

    void xqc_server_path_removed_notify_tramp(const xqc_cid_t *scid, uint64_t path_id, void *conn_user_data) {
    }

    xqc_int_t xqc_server_conn_closing_notify_tramp(xqc_connection_t *conn, const xqc_cid_t *cid, xqc_int_t err_code, void *conn_user_data) {
        return 0;
    }

    void xqc_server_conn_peer_addr_changed_notify_tramp(xqc_connection_t *conn, void *conn_user_data) {
    }

    void xqc_server_path_peer_addr_changed_notify_tramp(xqc_connection_t *conn, uint64_t path_id, void *conn_user_data) {
    }

    int xqc_server_conn_create_notify_tramp(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data, void *conn_proto_data) {
        if (conn_user_data) static_cast<XquicServer*>(conn_user_data)->on_conn_create_notify(conn, cid, conn_user_data, conn_proto_data);
        return 0;
    }
    
    int xqc_server_conn_close_notify_tramp(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data, void *conn_proto_data) {
        if (conn_user_data) static_cast<XquicServer*>(conn_user_data)->on_conn_close_notify(conn, cid, conn_user_data, conn_proto_data);
        return 0;
    }

    xqc_int_t xqc_server_stream_write_notify_tramp(xqc_stream_t *stream, void *strm_user_data) {
        if (strm_user_data) {
            user_stream_t *u_stream = (user_stream_t *)strm_user_data;
            if (u_stream && u_stream->server) {
                return ((XquicServer*)u_stream->server)->on_stream_write_notify(stream, strm_user_data);
            }
        }
        return 0;
    }

    xqc_int_t xqc_server_stream_read_notify_tramp(xqc_stream_t *stream, void *strm_user_data) {
        if (strm_user_data) {
            user_stream_t *u_stream = (user_stream_t *)strm_user_data;
            if (u_stream && u_stream->server) {
                return ((XquicServer*)u_stream->server)->on_stream_read_notify(stream, strm_user_data);
            }
        }
        return 0;
    }

    xqc_int_t xqc_server_stream_close_notify_tramp(xqc_stream_t *stream, void *strm_user_data) {
        if (strm_user_data) {
            user_stream_t *u_stream = (user_stream_t *)strm_user_data;
            if (u_stream && u_stream->server) {
                return ((XquicServer*)u_stream->server)->on_stream_close_notify(stream, strm_user_data);
            }
        }
        return 0;
    }

    int xqc_server_h3_conn_create_notify_tramp(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *h3c_user_data) {
        if (h3c_user_data) static_cast<XquicServer*>(h3c_user_data)->on_h3_conn_create_notify(conn, cid, h3c_user_data);
        return 0;
    }

    int xqc_server_h3_conn_close_notify_tramp(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *h3c_user_data) {
        if (h3c_user_data) static_cast<XquicServer*>(h3c_user_data)->on_h3_conn_close_notify(conn, cid, h3c_user_data);
        return 0;
    }

    xqc_int_t xqc_server_request_write_notify_tramp(xqc_h3_request_t *h3_request, void *h3s_user_data) {
        if (h3s_user_data) {
            user_stream_t *u_stream = (user_stream_t *)h3s_user_data;
            if (u_stream && u_stream->server) {
                return ((XquicServer*)u_stream->server)->on_request_write_notify(h3_request, h3s_user_data);
            }
        }
        return 0;
    }

    xqc_int_t xqc_server_request_read_notify_tramp(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *h3s_user_data) {
        if (h3s_user_data) {
            user_stream_t *u_stream = (user_stream_t *)h3s_user_data;
            if (u_stream && u_stream->server) {
                return ((XquicServer*)u_stream->server)->on_request_read_notify(h3_request, flag, h3s_user_data);
            }
        }
        return 0;
    }

    xqc_int_t xqc_server_request_close_notify_tramp(xqc_h3_request_t *h3_request, void *h3s_user_data) {
        if (h3s_user_data) {
            user_stream_t *u_stream = (user_stream_t *)h3s_user_data;
            if (u_stream && u_stream->server) {
                return ((XquicServer*)u_stream->server)->on_request_close_notify(h3_request, h3s_user_data);
            }
        }
        return 0;
    }
}

XquicServer::XquicServer() {
    engine_ = NULL;
    event_base_ = NULL;
    ev_engine_ = NULL;
    listen_fd_ = -1;
    ev_listen_ = NULL;
    
    port_ = 8443;
    ipv6_ = 0;
    transport_only_ = 0;
    cc_algo_ = 0; 
    cert_path_ = "./cert.crt";
    key_path_ = "./cert.key";
    log_path_ = "./slog";
}

XquicServer::~XquicServer() {
    if (ev_listen_) event_free(ev_listen_);
    if (listen_fd_ >= 0) close(listen_fd_);
    if (ev_engine_) event_free(ev_engine_);
    if (engine_) xqc_engine_destroy(engine_);
    if (event_base_) event_base_free(event_base_);
}

int XquicServer::start(int argc, char *argv[]) {
    if (init(argc, argv) != 0) {
        return -1;
    }
    run();
    return 0;
}

int XquicServer::init(int argc, char *argv[]) {
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port_ = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            cert_path_ = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_path_ = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0) {
            transport_only_ = 1;
        }
    }

    event_base_ = event_base_new();
    if (!event_base_) return -1;
    
    listen_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd_ < 0) return -1;
    
    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listen_fd_);
        return -1;
    }
    
    fcntl(listen_fd_, F_SETFL, O_NONBLOCK);
    
    ev_listen_ = event_new(event_base_, listen_fd_, EV_READ | EV_PERSIST, xqc_server_socket_trampoline, this);
    event_add(ev_listen_, NULL);

    // Initialize XQUIC Engine
    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        printf("xqc_engine_get_default_config error\n");
        return -1;
    }

    // Set log level
    config.cfg_log_level = XQC_LOG_DEBUG;
    config.cfg_log_event = 1;
    
    // SSL Config
    xqc_engine_ssl_config_t ssl_config;
    memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.private_key_file = const_cast<char*>(key_path_.c_str());
    ssl_config.cert_file = const_cast<char*>(cert_path_.c_str());

    // Engine Callbacks
    xqc_engine_callback_t engine_callback;
    memset(&engine_callback, 0, sizeof(engine_callback));
    engine_callback.set_event_timer = xqc_server_set_event_timer_tramp;
    engine_callback.keylog_cb = xqc_server_keylog_tramp;

    // Log callbacks
    engine_callback.log_callbacks.xqc_log_write_err = [](xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data) {
        printf("XQC LOG: %.*s\n", (int)size, (char*)buf);
    };
    engine_callback.log_callbacks.xqc_log_write_stat = [](xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data) {
        printf("XQC STAT: %.*s\n", (int)size, (char*)buf);
    };
    engine_callback.log_callbacks.xqc_qlog_event_write = nullptr;

    // Transport Callbacks
    xqc_transport_callbacks_t transport_cbs;
    memset(&transport_cbs, 0, sizeof(transport_cbs));
    transport_cbs.server_accept = xqc_server_accept_tramp;
    transport_cbs.server_refuse = xqc_server_refuse_tramp;
    transport_cbs.stateless_reset = xqc_server_stateless_reset_tramp;
    transport_cbs.write_socket = xqc_server_write_socket_tramp;
    transport_cbs.conn_update_cid_notify = xqc_server_conn_update_cid_notify_tramp;
    transport_cbs.save_token = xqc_server_save_token_tramp;
    transport_cbs.save_session_cb = xqc_server_save_session_tramp;
    transport_cbs.save_tp_cb = xqc_server_save_tp_tramp;
    transport_cbs.cert_verify_cb = xqc_server_cert_verify_tramp;
    transport_cbs.ready_to_create_path_notify = xqc_server_ready_to_create_path_notify_tramp;
    transport_cbs.path_created_notify = xqc_server_path_created_notify_tramp;
    transport_cbs.path_removed_notify = xqc_server_path_removed_notify_tramp;
    transport_cbs.conn_closing = xqc_server_conn_closing_notify_tramp;
    transport_cbs.conn_peer_addr_changed_notify = xqc_server_conn_peer_addr_changed_notify_tramp;
    transport_cbs.path_peer_addr_changed_notify = xqc_server_path_peer_addr_changed_notify_tramp;

    // Connection Callbacks
    xqc_conn_callbacks_t conn_cbs;
    memset(&conn_cbs, 0, sizeof(conn_cbs));
    conn_cbs.conn_create_notify = xqc_server_conn_create_notify_tramp;
    conn_cbs.conn_close_notify = xqc_server_conn_close_notify_tramp;

    // Stream Callbacks
    xqc_stream_callbacks_t stream_cbs;
    memset(&stream_cbs, 0, sizeof(stream_cbs));
    stream_cbs.stream_write_notify = xqc_server_stream_write_notify_tramp;
    stream_cbs.stream_read_notify = xqc_server_stream_read_notify_tramp;
    stream_cbs.stream_close_notify = xqc_server_stream_close_notify_tramp;

    engine_ = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl_config, &engine_callback, &transport_cbs, this);
    if (!engine_) {
        printf("xqc_engine_create error\n");
        return -1;
    }

    // Register HTTP/3 callbacks if not transport only
    if (!transport_only_) {
        xqc_h3_callbacks_t h3_cbs = {
            .h3c_cbs = {
                .h3_conn_create_notify = xqc_server_h3_conn_create_notify_tramp,
                .h3_conn_close_notify = xqc_server_h3_conn_close_notify_tramp,
            },
            .h3r_cbs = {
                .h3_request_close_notify = xqc_server_request_close_notify_tramp,
                .h3_request_read_notify = xqc_server_request_read_notify_tramp,
                .h3_request_write_notify = xqc_server_request_write_notify_tramp,
            },
        };

        if (xqc_h3_ctx_init(engine_, &h3_cbs) != XQC_OK) {
            printf("xqc_h3_ctx_init error\n");
            return -1;
        }
    }

    ev_engine_ = event_new(event_base_, -1, EV_PERSIST, xqc_server_engine_trampoline, this);
    
    return 0;
}

void XquicServer::run() {
    if (event_base_) {
        event_base_dispatch(event_base_);
    }
}

void XquicServer::on_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data) {
    printf("Server: Conn Created\n");
    user_conn_t *u_conn = (user_conn_t *)calloc(1, sizeof(user_conn_t));
    u_conn->server = this;
    u_conn->socket = listen_fd_;
    memcpy(&u_conn->cid, cid, sizeof(*cid));
    // Note: For transport connections, we'll set user data on streams when they're created
    // For H3 connections, the H3 layer manages connection-level user data
}

void XquicServer::on_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data) {
    printf("server: conn closed\n");
    if (user_data) free(user_data);
}

void XquicServer::on_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    printf("server: h3 conn created\n");
    
    user_conn_t *u_conn = (user_conn_t *)calloc(1, sizeof(user_conn_t));
    if (u_conn) {
        u_conn->server = this;
        u_conn->h3_conn = conn;
        memcpy(&u_conn->cid, cid, sizeof(*cid));
        
        xqc_h3_conn_set_user_data(conn, u_conn);
    }
}

void XquicServer::on_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    printf("server: h3 conn closed\n");
    if (user_data) free(user_data);
}

xqc_int_t XquicServer::on_stream_write_notify(xqc_stream_t *stream, void *user_data) {
    user_stream_t *u_stream = (user_stream_t *)user_data;
    if (u_stream) send_response(u_stream);
    return 0;
}

xqc_int_t XquicServer::on_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    user_stream_t *u_stream = (user_stream_t *)user_data;
    if (!u_stream) {
        u_stream = (user_stream_t *)calloc(1, sizeof(user_stream_t));
        u_stream->server = this;
        u_stream->stream = stream;
        u_stream->is_h3 = 0;
        xqc_stream_set_user_data(stream, u_stream);
    }

    unsigned char buf[4096];
    unsigned char fin = 0;
    ssize_t read = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
    
    if (read > 0) {
        printf("server: stream read %zd bytes\n", read);
        xqc_stream_send(stream, buf, read, fin);
    }
    return 0;
}

xqc_int_t XquicServer::on_stream_close_notify(xqc_stream_t *stream, void *user_data) {
    printf("server: stream closed\n");
    if (user_data) free(user_data);
    return 0;
}

xqc_int_t XquicServer::on_request_write_notify(xqc_h3_request_t *req, void *user_data) {
    user_stream_t *u_stream = (user_stream_t *)user_data;
    if (u_stream) send_h3_response(u_stream);
    return 0;
}

xqc_int_t XquicServer::on_request_read_notify(xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data) {
    user_stream_t *u_stream = (user_stream_t *)user_data;
    if (!u_stream) {
        u_stream = (user_stream_t *)calloc(1, sizeof(user_stream_t));
        u_stream->server = this;
        u_stream->h3_request = req;
        u_stream->is_h3 = 1;
        xqc_h3_request_set_user_data(req, u_stream);
    }

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(req, NULL);
        if (headers) {
            for (int i = 0; i < headers->count; i++) {
                printf("Header: %.*s = %.*s\n", 
                       (int)headers->headers[i].name.iov_len, (char*)headers->headers[i].name.iov_base,
                       (int)headers->headers[i].value.iov_len, (char*)headers->headers[i].value.iov_base);
            }
            free(headers);
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char buf[4096];
        unsigned char fin = 0;
        ssize_t read = xqc_h3_request_recv_body(req, buf, sizeof(buf), &fin);
        if (read > 0) {
            printf("server: h3 body read %zd bytes\n", read);
        }
        if (fin) {
            send_h3_response(u_stream);
        }
    }
    return 0;
}

xqc_int_t XquicServer::on_request_close_notify(xqc_h3_request_t *req, void *user_data) {
    printf("server: request closed\n");
    if (user_data) free(user_data);
    return 0;
}

void XquicServer::send_response(user_stream_t *user_stream) {
    if (!user_stream || !user_stream->stream) return;
    const char *resp = "Hello Transport";
    xqc_stream_send((xqc_stream_t*)user_stream->stream, (unsigned char*)resp, strlen(resp), 1);
}

void XquicServer::send_h3_response(user_stream_t *user_stream) {
    if (!user_stream || !user_stream->h3_request) return;

    xqc_http_header_t headers[] = {
        { {.iov_base = (void*)"content-length", .iov_len = 14}, {.iov_base = (void*)"26", .iov_len = 2} },
        { {.iov_base = (void*)"content-type", .iov_len = 12}, {.iov_base = (void*)"text/plain", .iov_len = 10} },
    };
    
    xqc_http_headers_t h_headers;
    h_headers.headers = headers;
    h_headers.count = 2;

    xqc_h3_request_send_headers((xqc_h3_request_t*)user_stream->h3_request, &h_headers, 0);

    const char *body = "Hello from Xquic H3";
    xqc_h3_request_send_body((xqc_h3_request_t*)user_stream->h3_request, (unsigned char*)body, strlen(body), 1);
}

void XquicServer::set_event_timer(xqc_msec_t wake_after) {
    if (ev_engine_) {
        struct timeval tv;
        tv.tv_sec = wake_after / 1000;
        tv.tv_usec = (wake_after % 1000) * 1000;
        event_add(ev_engine_, &tv);
    }
}

ssize_t XquicServer::write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr, socklen_t peer_addrlen, user_conn_t *user_conn) {
    if (!user_conn || user_conn->socket < 0) return -1;
    return sendto(user_conn->socket, buf, size, 0, peer_addr, peer_addrlen);
}

void XquicServer::on_engine_timer() {
    if (engine_) {
        xqc_engine_main_logic(engine_);
    }
}

void XquicServer::on_socket_event(int fd, short what) {
    if (what & EV_READ) {
        process_socket_read();
    }
}

void XquicServer::process_socket_read() {
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);
    unsigned char buf[4096];
    
    ssize_t n = recvfrom(listen_fd_, buf, sizeof(buf), 0, (struct sockaddr*)&peer_addr, &peer_addrlen);
    if (n < 0) return;

    // Use a stack-allocated structure to avoid memory leaks.
    // The engine may use this user_data for writing back packets before the connection
    // is fully established and conn_create_notify is called.
    // Once the connection is established, the engine will use the user_data
    // set by xqc_conn_set_transport_user_data in on_conn_create_notify.
    user_conn_t temp_user_conn;
    memset(&temp_user_conn, 0, sizeof(user_conn_t));
    temp_user_conn.server = this;
    temp_user_conn.socket = listen_fd_;

    if (engine_) {
        xqc_engine_packet_process(engine_, buf, n, 
                                  (struct sockaddr*)&peer_addr, peer_addrlen, 
                                  (struct sockaddr*)&peer_addr, peer_addrlen, 
                                  xqc_now(), 
                                  &temp_user_conn);
    }
}