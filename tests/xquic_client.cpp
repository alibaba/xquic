// xquic_client.cpp
#include "xquic_client.h"
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
#include <iostream>
#include <vector>
#include <string>

// Global active connection for socket events (Workaround if header cannot be modified)
static user_conn_t *g_active_u_conn = NULL;

// Helper to get current time in microseconds
static uint64_t xqc_now() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

// Trampolines
extern "C" {
    void xqc_client_engine_trampoline(int fd, short what, void *arg) {
        if (arg) static_cast<XquicClient*>(arg)->on_engine_timer();
    }

    void xqc_client_socket_trampoline(int fd, short what, void *arg) {
        if (arg) static_cast<XquicClient*>(arg)->on_socket_event(fd, what);
    }

    void xqc_client_set_event_timer_tramp(xqc_msec_t wake_after, void *user_data) {
        if (user_data) static_cast<XquicClient*>(user_data)->set_event_timer(wake_after);
    }

    ssize_t xqc_client_write_socket_tramp(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_conn) {
        if (user_conn) {
            user_conn_t *u_conn = (user_conn_t *)user_conn;
            if (u_conn && u_conn->client) {
                return ((XquicClient*)u_conn->client)->write_socket(buf, size, peer_addr, peer_addrlen, u_conn);
            }
        }
        return -1;
    }

    void xqc_client_keylog_tramp(const xqc_cid_t *scid, const char *line, void *user_data) {
        (void)scid;
        (void)line;
        (void)user_data;
    }

    int xqc_client_accept_tramp(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data) {
        return 0;
    }

    void xqc_client_refuse_tramp(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data) {
    }

    ssize_t xqc_client_stateless_reset_tramp(const unsigned char *buf, size_t size,
        const struct sockaddr *peer_addr, socklen_t peer_addrlen,
        const struct sockaddr *local_addr, socklen_t local_addrlen,
        void *user_data) {
        return -1;
    }

    void xqc_client_conn_update_cid_notify_tramp(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
        const xqc_cid_t *new_cid, void *conn_user_data) {
    }

    void xqc_client_save_token_tramp(const unsigned char *token, uint32_t token_len, void *conn_user_data) {
    }

    void xqc_client_save_session_tramp(const char *data, size_t data_len, void *conn_user_data) {
    }

    void xqc_client_save_tp_tramp(const char *data, size_t data_len, void *conn_user_data) {
    }

    int xqc_client_cert_verify_tramp(const unsigned char *certs[], const size_t cert_len[],
        size_t certs_len, void *conn_user_data) {
        return 0;
    }

    void xqc_client_ready_to_create_path_notify_tramp(const xqc_cid_t *scid, void *conn_user_data) {
    }

    int xqc_client_path_created_notify_tramp(xqc_connection_t *conn,
        const xqc_cid_t *scid, uint64_t path_id, void *conn_user_data) {
        return 0;
    }

    void xqc_client_path_removed_notify_tramp(const xqc_cid_t *scid, uint64_t path_id, void *conn_user_data) {
    }

    int xqc_client_conn_closing_notify_tramp(xqc_connection_t *conn, const xqc_cid_t *cid, xqc_int_t err_code, void *conn_user_data) {
        return 0;
    }

    void xqc_client_conn_peer_addr_changed_notify_tramp(xqc_connection_t *conn, void *conn_user_data) {
    }

    void xqc_client_path_peer_addr_changed_notify_tramp(xqc_connection_t *conn, uint64_t path_id, void *conn_user_data) {
    }

    int xqc_client_conn_create_notify_tramp(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data, void *conn_proto_data) {
        if (conn_user_data) static_cast<XquicClient*>(conn_user_data)->on_conn_create_notify(conn, cid, conn_user_data, conn_proto_data);
        return 0;
    }

    int xqc_client_conn_close_notify_tramp(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data, void *conn_proto_data) {
        if (conn_user_data) static_cast<XquicClient*>(conn_user_data)->on_conn_close_notify(conn, cid, conn_user_data, conn_proto_data);
        return 0;
    }

    void xqc_client_conn_handshake_finished_tramp(xqc_connection_t *conn, void *conn_user_data, void *conn_proto_data) {
        if (conn_user_data) static_cast<XquicClient*>(conn_user_data)->on_conn_handshake_finished(conn, conn_user_data, conn_proto_data);
    }

    void xqc_client_conn_ping_acked_tramp(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *conn_user_data, void *conn_proto_data) {
        if (conn_user_data) static_cast<XquicClient*>(conn_user_data)->on_conn_ping_acked(conn, cid, ping_user_data, conn_user_data, conn_proto_data);
    }

    void xqc_client_conn_update_cid_tramp(xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *conn_user_data) {
        if (conn_user_data) static_cast<XquicClient*>(conn_user_data)->on_conn_update_cid(conn, retire_cid, new_cid, conn_user_data);
    }

    // H3 Callbacks
    int xqc_client_h3_conn_create_notify_tramp(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
        if (user_data) {
            user_conn_t *u_conn = (user_conn_t *)user_data;
            if (u_conn->client) {
                XquicClient *client = (XquicClient *)u_conn->client;
                client->on_h3_conn_create_notify(conn, cid, u_conn);
            }
        }
        return 0;
    }

    int xqc_client_h3_conn_close_notify_tramp(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *h3c_user_data) {
        if (h3c_user_data) {
            user_conn_t *u_conn = (user_conn_t *)h3c_user_data;
            if (u_conn->client) {
                XquicClient *client = (XquicClient *)u_conn->client;
                client->on_h3_conn_close_notify(conn, cid, u_conn);
            }
        }
        return 0;
    }

    void xqc_client_h3_conn_handshake_finished_tramp(xqc_h3_conn_t *h3_conn, void *h3c_user_data) {
        if (h3c_user_data) {
            user_conn_t *u_conn = (user_conn_t *)h3c_user_data;
            if (u_conn->client) {
                XquicClient *client = (XquicClient *)u_conn->client;
                client->on_h3_conn_handshake_finished(h3_conn, u_conn);
            }
        }
    }

    void xqc_client_h3_conn_ping_acked_tramp(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *h3c_user_data) {
        if (h3c_user_data) {
            user_conn_t *u_conn = (user_conn_t *)h3c_user_data;
            if (u_conn->client) {
                XquicClient *client = (XquicClient *)u_conn->client;
                client->on_h3_conn_ping_acked(conn, cid, ping_user_data, u_conn);
            }
        }
    }

    void xqc_client_h3_conn_update_cid_tramp(xqc_h3_conn_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *h3c_user_data) {
        if (h3c_user_data) {
            user_conn_t *u_conn = (user_conn_t *)h3c_user_data;
            if (u_conn->client) {
                XquicClient *client = (XquicClient *)u_conn->client;
                client->on_h3_conn_update_cid(conn, retire_cid, new_cid, u_conn);
            }
        }
    }

    // Stream Callbacks
    xqc_int_t xqc_client_stream_write_notify_tramp(xqc_stream_t *stream, void *strm_user_data) {
        if (strm_user_data) {
            user_stream_t *u_stream = (user_stream_t *)strm_user_data;
            if (u_stream && u_stream->client) {
                return ((XquicClient*)u_stream->client)->on_stream_write_notify(stream, strm_user_data);
            }
        }
        return 0;
    }

    xqc_int_t xqc_client_stream_read_notify_tramp(xqc_stream_t *stream, void *strm_user_data) {
        if (strm_user_data) {
            user_stream_t *u_stream = (user_stream_t *)strm_user_data;
            if (u_stream && u_stream->client) {
                return ((XquicClient*)u_stream->client)->on_stream_read_notify(stream, strm_user_data);
            }
        }
        return 0;
    }

    xqc_int_t xqc_client_stream_close_notify_tramp(xqc_stream_t *stream, void *strm_user_data) {
        if (strm_user_data) {
            user_stream_t *u_stream = (user_stream_t *)strm_user_data;
            if (u_stream && u_stream->client) {
                return ((XquicClient*)u_stream->client)->on_stream_close_notify(stream, strm_user_data);
            }
        }
        return 0;
    }

    // Request Callbacks
    xqc_int_t xqc_client_request_write_notify_tramp(xqc_h3_request_t *h3_request, void *h3s_user_data) {
        if (h3s_user_data) {
            user_stream_t *u_stream = (user_stream_t *)h3s_user_data;
            if (u_stream && u_stream->client) {
                return ((XquicClient*)u_stream->client)->on_request_write_notify(h3_request, h3s_user_data);
            }
        }
        return 0;
    }

    xqc_int_t xqc_client_request_read_notify_tramp(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *h3s_user_data) {
        if (h3s_user_data) {
            user_stream_t *u_stream = (user_stream_t *)h3s_user_data;
            if (u_stream && u_stream->client) {
                return ((XquicClient*)u_stream->client)->on_request_read_notify(h3_request, flag, h3s_user_data);
            }
        }
        return 0;
    }

    xqc_int_t xqc_client_request_close_notify_tramp(xqc_h3_request_t *h3_request, void *h3s_user_data) {
        if (h3s_user_data) {
            user_stream_t *u_stream = (user_stream_t *)h3s_user_data;
            if (u_stream && u_stream->client) {
                return ((XquicClient*)u_stream->client)->on_request_close_notify(h3_request, h3s_user_data);
            }
        }
        return 0;
    }
}

XquicClient::XquicClient() {
    engine_ = NULL;
    event_base_ = NULL;
    ev_engine_ = NULL;
    
    // Defaults
    port_ = 8443;
    server_ip_ = "127.0.0.1";
    transport_only_ = 0;
    log_path_ = "./clog";
    send_body_size_ = 1024;
    echo_check_ = 0;
    save_file_ = 0;
    write_file_ = "./received_data";
}

XquicClient::~XquicClient() {
    if (ev_engine_) {
        event_free(ev_engine_);
        ev_engine_ = NULL;
    }
    if (engine_) {
        xqc_engine_destroy(engine_);
        engine_ = NULL;
    }
    if (event_base_) {
        event_base_free(event_base_);
        event_base_ = NULL;
    }
}

int XquicClient::init(int argc, char *argv[]) {
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            server_ip_ = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port_ = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0) {
            transport_only_ = 1;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            send_body_size_ = atol(argv[++i]);
        } else if (strcmp(argv[i], "-E") == 0) {
            echo_check_ = 1;
        } else if (strcmp(argv[i], "-S") == 0) {
            save_file_ = 1;
        }
    }

    event_base_ = event_base_new();
    if (!event_base_) return -1;

    // Initialize XQUIC Engine
    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        printf("xqc_engine_get_default_config error\n");
        return -1;
    }

    config.cfg_log_level = XQC_LOG_DEBUG;
    config.cfg_log_event = 1;
    
    xqc_engine_ssl_config_t ssl_config;
    memset(&ssl_config, 0, sizeof(ssl_config));
    // In a real client, you might need to configure cert verification options here

    ssl_config.ciphers = XQC_TLS_CIPHERS;
    ssl_config.groups = XQC_TLS_GROUPS;


    xqc_engine_callback_t engine_callback;
    memset(&engine_callback, 0, sizeof(engine_callback));
    engine_callback.set_event_timer = xqc_client_set_event_timer_tramp;
    engine_callback.keylog_cb = xqc_client_keylog_tramp;

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
    transport_cbs.server_accept = xqc_client_accept_tramp;
    transport_cbs.server_refuse = xqc_client_refuse_tramp;
    transport_cbs.stateless_reset = xqc_client_stateless_reset_tramp;
    transport_cbs.write_socket = xqc_client_write_socket_tramp;
    transport_cbs.conn_update_cid_notify = xqc_client_conn_update_cid_notify_tramp;
    transport_cbs.save_token = xqc_client_save_token_tramp;
    transport_cbs.save_session_cb = xqc_client_save_session_tramp;
    transport_cbs.save_tp_cb = xqc_client_save_tp_tramp;
    transport_cbs.cert_verify_cb = xqc_client_cert_verify_tramp;
    transport_cbs.ready_to_create_path_notify = xqc_client_ready_to_create_path_notify_tramp;
    transport_cbs.path_created_notify = xqc_client_path_created_notify_tramp;
    transport_cbs.path_removed_notify = xqc_client_path_removed_notify_tramp;
    transport_cbs.conn_closing = xqc_client_conn_closing_notify_tramp;
    transport_cbs.conn_peer_addr_changed_notify = xqc_client_conn_peer_addr_changed_notify_tramp;
    transport_cbs.path_peer_addr_changed_notify = xqc_client_path_peer_addr_changed_notify_tramp;

    // Connection Callbacks
    xqc_conn_callbacks_t conn_cbs;
    memset(&conn_cbs, 0, sizeof(conn_cbs));
    conn_cbs.conn_create_notify = xqc_client_conn_create_notify_tramp;
    conn_cbs.conn_close_notify = xqc_client_conn_close_notify_tramp;
    conn_cbs.conn_handshake_finished = xqc_client_conn_handshake_finished_tramp;
    conn_cbs.conn_ping_acked = xqc_client_conn_ping_acked_tramp;

    // Stream Callbacks
    xqc_stream_callbacks_t stream_cbs;
    memset(&stream_cbs, 0, sizeof(stream_cbs));
    stream_cbs.stream_write_notify = xqc_client_stream_write_notify_tramp;
    stream_cbs.stream_read_notify = xqc_client_stream_read_notify_tramp;
    stream_cbs.stream_close_notify = xqc_client_stream_close_notify_tramp;

    engine_ = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &ssl_config, &engine_callback, &transport_cbs, this);
    if (!engine_) {
        printf("xqc_engine_create error\n");
        return -1;
    }

    // Register H3 if not transport only
    if (!transport_only_) {
        xqc_h3_callbacks_t h3_cbs = {
            .h3c_cbs = {
                .h3_conn_create_notify = xqc_client_h3_conn_create_notify_tramp,
                .h3_conn_close_notify = xqc_client_h3_conn_close_notify_tramp,
            },
            .h3r_cbs = {
                .h3_request_close_notify = xqc_client_request_close_notify_tramp,
                .h3_request_read_notify = xqc_client_request_read_notify_tramp,
                .h3_request_write_notify = xqc_client_request_write_notify_tramp,
            },
        };

        if (xqc_h3_ctx_init(engine_, &h3_cbs) != XQC_OK) {
            printf("xqc_h3_ctx_init error\n");
            return -1;
        }
    }

    // Register ALPN for transport connections
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = xqc_client_conn_create_notify_tramp,
            .conn_close_notify = xqc_client_conn_close_notify_tramp,
            .conn_handshake_finished = xqc_client_conn_handshake_finished_tramp,
            .conn_ping_acked = xqc_client_conn_ping_acked_tramp,
        },
        .stream_cbs = {
            .stream_write_notify = xqc_client_stream_write_notify_tramp,
            .stream_read_notify = xqc_client_stream_read_notify_tramp,
            .stream_close_notify = xqc_client_stream_close_notify_tramp,
        }
    };

    // Register transport ALPN regardless of transport_only_ setting to handle both cases
    if (xqc_engine_register_alpn(engine_, "transport", 9, &ap_cbs, NULL) != XQC_OK) {
        printf("Failed to register transport ALPN!\n");
        return -1;
    }

    ev_engine_ = event_new(event_base_, -1, EV_PERSIST, xqc_client_engine_trampoline, this);
    event_add(ev_engine_, NULL);

    // Create Connection
    user_conn_t *u_conn = (user_conn_t *)calloc(1, sizeof(user_conn_t));
    u_conn->client = this;
    u_conn->h3 = !transport_only_;  // 如果transport_only_为true，则h3为false；反之亦然
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    inet_pton(AF_INET, server_ip_.c_str(), &addr.sin_addr);
    
    u_conn->peer_addr = (struct sockaddr *)malloc(sizeof(addr));
    memcpy(u_conn->peer_addr, &addr, sizeof(addr));
    u_conn->peer_addrlen = sizeof(addr);
    
    u_conn->fd = socket(AF_INET, SOCK_DGRAM, 0);
    fcntl(u_conn->fd, F_SETFL, O_NONBLOCK);
    
    u_conn->ev_socket = event_new(event_base_, u_conn->fd, EV_READ | EV_PERSIST, xqc_client_socket_trampoline, this);
    event_add(u_conn->ev_socket, NULL);

    // Set global active connection for socket processing
    g_active_u_conn = u_conn;

    // Connect
    if (transport_only_) {
        xqc_conn_settings_t conn_settings;
        memset(&conn_settings, 0, sizeof(conn_settings));
        // xqc_default_conn_settings(&conn_settings);
        conn_settings.proto_version = XQC_VERSION_V1;  // Ensure protocol version is set correctly
        
        xqc_conn_ssl_config_t ssl_config;
        memset(&ssl_config, 0, sizeof(ssl_config));
        
        // Additional SSL configuration for better compatibility
        // ssl_config.tls_groups.group_arr = NULL;
        // ssl_config.tls_groups.group_num = 0;
        ssl_config.session_ticket_data = NULL;
        ssl_config.transport_parameter_data = NULL;
        
        const xqc_cid_t *cid = xqc_connect(engine_, &conn_settings, NULL, 0, server_ip_.c_str(), 1, &ssl_config,
                                          (struct sockaddr*)&addr, sizeof(addr), "transport", u_conn);
        if (cid == NULL) {
            printf("xqc_connect error\n");
            return -1;
        }
        memcpy(&u_conn->cid, cid, sizeof(*cid));
    } else {
        // H3 Connect
        xqc_conn_settings_t conn_settings;
        memset(&conn_settings, 0, sizeof(conn_settings));
        // xqc_default_conn_settings(&conn_settings);
        conn_settings.proto_version = XQC_VERSION_V1;  // Ensure protocol version is set correctly
        
        xqc_conn_ssl_config_t ssl_config;
        memset(&ssl_config, 0, sizeof(ssl_config));
        
        // Additional SSL configuration for better compatibility
        // ssl_config.tls_groups.group_arr = NULL;
        // ssl_config.tls_groups.group_num = 0;
        ssl_config.session_ticket_data = NULL;
        ssl_config.transport_parameter_data = NULL;
        
        // Updated xqc_h3_connect signature: added token/token_len params (NULL, 0) before server_name
        const xqc_cid_t *cid = xqc_h3_connect(engine_, &conn_settings, NULL, 0, server_ip_.c_str(), 1, &ssl_config,
                                             (struct sockaddr*)&addr, sizeof(addr), u_conn);
        if (cid == NULL) {
            printf("xqc_h3_connect error\n");
            return -1;
        }
        memcpy(&u_conn->cid, cid, sizeof(*cid));
    }
    
    return 0;
}

int XquicClient::start(int argc, char *argv[]) {
    if (init(argc, argv) != 0) {
        return -1;
    }
    
    // Run the event loop
    run();
    return 0;
}

void XquicClient::run() {
    if (event_base_) {
        event_base_dispatch(event_base_);
    }
}

void XquicClient::on_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data) {
    printf("client: conn created\n");
}

void XquicClient::on_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data) {
    printf("client: conn closed\n");
}

void XquicClient::on_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data) {
    printf("client: handshake finished\n");
    user_conn_t *u_conn = (user_conn_t *)user_data;
    if (u_conn && transport_only_) {
        // Create Stream
        user_stream_t *u_stream = (user_stream_t *)calloc(1, sizeof(user_stream_t));
        u_stream->client = this;
        u_stream->user_conn = u_conn;
        u_stream->start_time = xqc_now();
        
        xqc_stream_t *stream = xqc_stream_create(engine_, &u_conn->cid, NULL, u_stream);
        if (stream) {
            u_stream->stream = stream;
            xqc_stream_set_user_data(stream, u_stream);
            
            // Prepare send body
            if (send_body_size_ > 0) {
                u_stream->send_body_max = 100*1024*1024; // Max limit
                u_stream->send_body = (char*)malloc(send_body_size_);
                if (u_stream->send_body) {
                    memset(u_stream->send_body, 1, send_body_size_);
                    u_stream->send_body_len = send_body_size_;
                }
            }
            
            char data[] = "Hello Server";
            xqc_stream_send(stream, (unsigned char*)data, strlen(data), 1);
        }
    }
}

void XquicClient::on_conn_ping_acked(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data, void *conn_proto_data) {
    // printf("client: ping acked\n");
}

void XquicClient::on_conn_update_cid(xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data) {
    // Update CID in user_conn if tracked
    if (user_data) {
        user_conn_t *u_conn = (user_conn_t *)user_data;
        memcpy(&u_conn->cid, new_cid, sizeof(*new_cid));
    }
}

// H3 Callbacks
void XquicClient::on_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    printf("Client: H3 Conn Created\n");
    user_conn_t *u_conn = (user_conn_t *)user_data;
    if (u_conn) {
        u_conn->h3_conn = conn;
        // Send Request
        send_request(u_conn);
    }
}

void XquicClient::on_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    printf("client: h3 conn closed\n");
}

void XquicClient::on_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data) {
    printf("client: h3 handshake finished\n");
}

void XquicClient::on_h3_conn_ping_acked(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data) {
    // printf("client: h3 ping acked\n");
}

void XquicClient::on_h3_conn_update_cid(xqc_h3_conn_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data) {
     if (user_data) {
        user_conn_t *u_conn = (user_conn_t *)user_data;
        memcpy(&u_conn->cid, new_cid, sizeof(*new_cid));
    }
}

// Stream Callbacks
xqc_int_t XquicClient::on_stream_write_notify(xqc_stream_t *stream, void *user_data) {
    user_stream_t *u_stream = (user_stream_t *)user_data;
    if (u_stream) {
        send_stream_data(stream, u_stream);
    }
    return 0;
}

xqc_int_t XquicClient::on_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    user_stream_t *user_stream = (user_stream_t *)user_data;
    if (!user_stream) return 0;

    unsigned char buf[4096];
    unsigned char fin = 0;
    ssize_t read = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
    
    if (read > 0) {
        printf("client: stream read %zd bytes\n", read);
        
        // Handle receive logic (echo check, save file, etc.)
        if (echo_check_ && user_stream->recv_body == NULL) {
            user_stream->recv_body = (char*)malloc(user_stream->send_body_len);
        }
        if (echo_check_ && user_stream->recv_body) {
            if (user_stream->recv_body_len + read <= user_stream->send_body_len) {
                memcpy(user_stream->recv_body + user_stream->recv_body_len, buf, read);
            }
        }
        user_stream->recv_body_len += read;
        
        if (fin) {
            user_stream->recv_fin = 1;
            printf("client: stream finished. recv_len=%zu, send_len=%zu\n", 
                   user_stream->recv_body_len, user_stream->send_body_len);
            
            if (echo_check_ && user_stream->recv_body_len == user_stream->send_body_len) {
                if (memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len) == 0) {
                    printf("====>Echo Check Success\n");
                } else {
                    printf("====>Echo Check Failed\n");
                }
            }
        }
    }
    return 0;
}

xqc_int_t XquicClient::on_stream_close_notify(xqc_stream_t *stream, void *user_data) {
    printf("client: stream closed\n");
    if (user_data) {
        user_stream_t *u_stream = (user_stream_t *)user_data;
        if (u_stream->recv_body_fp) fclose(u_stream->recv_body_fp);
        if (u_stream->recv_body) free(u_stream->recv_body);
        if (u_stream->send_body) free(u_stream->send_body);
        free(user_data);
    }
    return 0;
}

// Request Callbacks
xqc_int_t XquicClient::on_request_write_notify(xqc_h3_request_t *req, void *user_data) {
    // Trigger sending body if headers sent
    return 0;
}

xqc_int_t XquicClient::on_request_read_notify(xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data) {
    user_stream_t *user_stream = (user_stream_t *)user_data;
    if (!user_stream) return 0;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(req, NULL);
        if (headers) {
            for (int i = 0; i < headers->count; i++) {
                printf("client header: %.*s = %.*s\n", 
                       (int)headers->headers[i].name.iov_len, (char*)headers->headers[i].name.iov_base,
                       (int)headers->headers[i].value.iov_len, (char*)headers->headers[i].value.iov_base);
            }
            free(headers); 
        }
        user_stream->header_recvd = 1;
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char buf[4096];
        unsigned char fin = 0;
        ssize_t read = xqc_h3_request_recv_body(req, buf, sizeof(buf), &fin);
        if (read > 0) {
            printf("client: h3 body read %zd bytes\n", read);
            
            // Save to file if requested
            if (save_file_ && user_stream->recv_body_fp == NULL) {
                user_stream->recv_body_fp = fopen(write_file_.c_str(), "wb");
            }
            if (save_file_ && user_stream->recv_body_fp) {
                fwrite(buf, 1, read, user_stream->recv_body_fp);
                fflush(user_stream->recv_body_fp);
            }

            // Echo check
            if (echo_check_ && user_stream->recv_body) {
                 if (user_stream->recv_body_len + read <= user_stream->send_body_len) {
                    memcpy(user_stream->recv_body + user_stream->recv_body_len, buf, read);
                 }
            }
            user_stream->recv_body_len += read;
        }
        if (fin) {
            user_stream->recv_fin = 1;
            printf("client: request finished. recv_len=%zu, send_len=%zu\n", 
                   user_stream->recv_body_len, user_stream->send_body_len);
            
            if (echo_check_ && user_stream->recv_body_len == user_stream->send_body_len) {
                if (memcmp(user_stream->send_body, user_stream->recv_body, user_stream->send_body_len) == 0) {
                    printf("====>Echo Check Success\n");
                } else {
                    printf("====>Echo Check Failed\n");
                }
            }
            
            if (save_file_ && user_stream->recv_body_fp) {
                fclose(user_stream->recv_body_fp);
                user_stream->recv_body_fp = NULL;
            }
        }
    }
    return 0;
}

xqc_int_t XquicClient::on_request_close_notify(xqc_h3_request_t *req, void *user_data) {
    printf("client: request closed\n");
    if (user_data) {
        user_stream_t *u_stream = (user_stream_t *)user_data;
        if (u_stream->recv_body_fp) fclose(u_stream->recv_body_fp);
        if (u_stream->recv_body) free(u_stream->recv_body);
        if (u_stream->send_body) free(u_stream->send_body);
        free(user_data);
    }
    return 0;
}

void XquicClient::send_stream_data(xqc_stream_t *stream, user_stream_t *user_stream) {
    if (!user_stream || !stream) return;
    
    if (user_stream->send_offset < user_stream->send_body_len) {
        size_t remaining = user_stream->send_body_len - user_stream->send_offset;
        size_t to_send = remaining < 4096 ? remaining : 4096;
        
        ssize_t sent = xqc_stream_send(stream, 
                                       (unsigned char*)(user_stream->send_body + user_stream->send_offset), 
                                       to_send, 
                                       (to_send == remaining) ? 1 : 0); // Set FIN if last chunk
        
        if (sent > 0) {
            user_stream->send_offset += sent;
        }
    }
}

void XquicClient::send_request(user_conn_t *u_conn) {
    if (!u_conn) return;

    user_stream_t *user_stream = (user_stream_t *)calloc(1, sizeof(user_stream_t));
    if (!user_stream) return;
    
    user_stream->client = this;
    user_stream->user_conn = u_conn;
    user_stream->start_time = xqc_now();
    
    // Prepare send body
    if (send_body_size_ > 0) {
        user_stream->send_body_max = 100*1024*1024; // Max limit
        user_stream->send_body = (char*)malloc(send_body_size_);
        if (user_stream->send_body) {
            memset(user_stream->send_body, 1, send_body_size_);
            user_stream->send_body_len = send_body_size_;
        }
    }

    // Create H3 Request
    xqc_h3_request_t *req = xqc_h3_request_create(engine_, &u_conn->cid, NULL, user_stream);
    if (req) {
        user_stream->h3_request = req;
        xqc_h3_request_set_user_data(req, user_stream);
        
        // Send Headers
        std::vector<std::string> headers_str = {":method: GET", ":path: /", ":scheme: https"};
        std::vector<xqc_http_header_t> headers;
        
        for (const auto& h : headers_str) {
            size_t pos = h.find(':');
            if (pos != std::string::npos) {
                xqc_http_header_t header;
                // Fix dangling pointer by duplicating string
                std::string name = h.substr(0, pos);
                std::string value = h.substr(pos+1);
                
                header.name.iov_base = strdup(name.c_str());
                header.name.iov_len = name.length();
                header.value.iov_base = strdup(value.c_str());
                header.value.iov_len = value.length();
                headers.push_back(header);
            }
        }
        
        xqc_http_headers_t h_headers;
        h_headers.headers = headers.data();
        h_headers.count = headers.size();
        
        xqc_h3_request_send_headers(req, &h_headers, 0);
        
        // Free duplicated strings after sending headers if API doesn't take ownership
        for (auto& hdr : headers) {
            free((void*)hdr.name.iov_base);
            free((void*)hdr.value.iov_base);
        }
        
        user_stream->header_sent = 1;
        
        // Send Body if any
        if (user_stream->send_body_len > 0) {
             xqc_h3_request_send_body(req, (unsigned char*)user_stream->send_body, user_stream->send_body_len, 1);
        }
    }
}

void XquicClient::set_event_timer(xqc_msec_t wake_after) {
    if (ev_engine_) {
        struct timeval tv;
        tv.tv_sec = wake_after / 1000;
        tv.tv_usec = (wake_after % 1000) * 1000;
        event_add(ev_engine_, &tv);
    }
}

ssize_t XquicClient::write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr, socklen_t peer_addrlen, user_conn_t *user_conn) {
    if (!user_conn || user_conn->fd < 0) return -1;
    return sendto(user_conn->fd, buf, size, 0, peer_addr, peer_addrlen);
}

void XquicClient::on_engine_timer() {
    if (engine_) {
        xqc_engine_main_logic(engine_);
    }
}

void XquicClient::on_socket_event(int fd, short what) {
    if (what & EV_READ) {
        process_socket_read();
    }
}

void XquicClient::process_socket_read() {
    if (!g_active_u_conn || !engine_) {
        return;
    }

    unsigned char buf[4096];
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);
    
    ssize_t n = recvfrom(g_active_u_conn->fd, buf, sizeof(buf), 0, (struct sockaddr*)&peer_addr, &peer_addrlen);
    if (n > 0) {
         xqc_engine_packet_process(engine_, buf, n, g_active_u_conn->peer_addr, g_active_u_conn->peer_addrlen, (struct sockaddr*)&peer_addr, peer_addrlen, xqc_now(), g_active_u_conn);
    }
}