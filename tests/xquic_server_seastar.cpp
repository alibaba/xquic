#include "xquic_server_seastar.hh"
#include "user_conn.h" // Your existing struct definitions
#include <seastar/core/reactor.hh>
#include <seastar/net/inet_address.hh>
#include <fcntl.h>
#include <unistd.h>

// Helper to convert seastar address to sockaddr
static void seastar_addr_to_sockaddr(const seastar::socket_address& src, struct sockaddr* dst, socklen_t* len) {
    if (src.is_ipv4()) {
        auto& ipv4 = src.as_ipv4_addr();
        auto* in = reinterpret_cast<sockaddr_in*>(dst);
        memset(in, 0, sizeof(*in));
        in->sin_family = AF_INET;
        in->sin_port = htons(ipv4.port());
        in->sin_addr.s_addr = htonl(ipv4.ip().ip());
        *len = sizeof(sockaddr_in);
    } else {
        auto& ipv6 = src.as_ipv6_addr();
        auto* in6 = reinterpret_cast<sockaddr_in6*>(dst);
        memset(in6, 0, sizeof(*in6));
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons(ipv6.port());
        memcpy(in6->sin6_addr.s6_addr, ipv6.ip().ip(), 16);
        *len = sizeof(sockaddr_in6);
    }
}

XquicSeastarServer::XquicSeastarServer() 
    : _engine_timer([this]() { on_engine_timer_expire(); })
    , _engine(nullptr) {
}

XquicSeastarServer::~XquicSeastarServer() {
    if (_engine) {
        xqc_engine_destroy(_engine);
    }
}

void XquicSeastarServer::init_xquic_engine() {
    xqc_platform_init_env();

    xqc_engine_ssl_config_t ssl_config;
    memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.cert_file = _cert_path.c_str();
    ssl_config.private_key_file = _key_path.c_str();
    ssl_config.ciphers = XQC_TLS_CIPHERS;
    ssl_config.groups = XQC_TLS_GROUPS;

    xqc_config_t config;
    xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER);
    config.cfg_log_level = XQC_LOG_INFO;

    xqc_engine_callback_t engine_cb = {
        .set_event_timer = XquicSeastarServer::ss_set_event_timer,
        .keylog_cb = nullptr, // Optional
    };

    xqc_transport_callbacks_t trans_cb = {
        .write_socket = XquicSeastarServer::ss_write_socket,
    };

    // Pass 'this' as user_data so trampolines can find us
    _engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl_config, &engine_cb, &trans_cb, this);
    
    // Initialize H3 or Transport ALPN here similar to previous example
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = [](xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
                std::cout << "H3 Conn Created\n";
            },
            .h3_conn_close_notify = [](xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
                std::cout << "H3 Conn Closed\n";
            },
        },
        .h3r_cbs = {
            .h3_request_read_notify = [](xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data) {
                if (flag & XQC_REQ_NOTIFY_READ_BODY) {
                    char buf[1024];
                    unsigned char fin = 0;
                    ssize_t n = xqc_h3_request_recv_body(req, buf, sizeof(buf), &fin);
                    if (n > 0) {
                        std::cout << "Received H3 body: " << std::string(buf, n) << std::endl;
                        // Send response
                        xqc_http_header_t headers[] = {
                            { {.iov_base = (void*)":status", .iov_len = 7}, {.iov_base = (void*)"200", .iov_len = 3}, 0 },
                        };
                        xqc_http_headers_t h = { .headers = headers, .count = 1 };
                        xqc_h3_request_send_headers(req, &h, 0);
                        const char* resp = "Hello from Seastar Xquic";
                        xqc_h3_request_send_body(req, (const unsigned char*)resp, strlen(resp), 1);
                    }
                }
            },
        }
    };
    xqc_h3_ctx_init(_engine, &h3_cbs);
}

seastar::future<> XquicSeastarServer::start(uint16_t port, const std::string& cert_path, const std::string& key_path) {
    _cert_path = cert_path;
    _key_path = key_path;

    init_xquic_engine();

    // Create UDP channel
    seastar::socket_address addr(seastar::ipv4_addr("0.0.0.0", port));
    _udp_channel = std::make_unique<seastar::udp_channel>(seastar::engine().net(), addr);

    std::cout << "Seastar Xquic Server started on port " << port << std::endl;

    // Start listening loop
    // Note: In a real app, you might want to handle this in a background fiber
    seastar::keep_doing([this]() {
        return _udp_channel->receive()
            .then([this](std::tuple<seastar::net::packet, seastar::socket_address> data) {
                auto& [pkt, addr] = data;
                on_packet_received(std::move(pkt), addr);
            });
    }).handle_exception([](std::exception_ptr e) {
        std::cerr << "UDP receive error: " << std::current_exception() << std::endl;
    });

    return seastar::make_ready_future<>();
}

seastar::future<> XquicSeastarServer::stop() {
    _engine_timer.cancel();
    if (_udp_channel) {
        _udp_channel->shutdown_input();
    }
    return seastar::make_ready_future<>();
}

void XquicSeastarServer::on_packet_received(seastar::net::packet pkt, seastar::socket_address addr) {
    // Process each fragment in the packet
    for (auto& frag : pkt.fragments()) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        seastar_addr_to_sockaddr(addr, (struct sockaddr*)&peer_addr, &peer_len);

        // Get local address (simplified, assuming bound to 0.0.0.0)
        struct sockaddr_storage local_addr;
        socklen_t local_len = sizeof(local_addr);
        // In Seastar, getting local addr from udp_channel is tricky, usually we know it.
        // For demo, we assume IPv4 any
        auto* in = reinterpret_cast<sockaddr_in*>(&local_addr);
        memset(in, 0, sizeof(*in));
        in->sin_family = AF_INET;
        in->sin_port = htons(_udp_channel->local_address().port()); // Might need specific API
        local_len = sizeof(sockaddr_in);

        // Create dummy user_conn for context
        user_conn_t* user_conn = (user_conn_t*)calloc(1, sizeof(user_conn_t));
        memcpy(&user_conn->peer_addr, &peer_addr, peer_len);
        user_conn->peer_addrlen = peer_len;
        memcpy(&user_conn->local_addr, &local_addr, local_len);
        user_conn->local_addrlen = local_len;
        
        // Store pointer to server if needed in write_socket trampoline
        // user_conn->server_instance = this; 

        uint64_t now = seastar::reactor::now().time_since_epoch().count() / 1000; // microseconds

        xqc_engine_packet_process(_engine, (const unsigned char*)frag.base, frag.size,
                                  (struct sockaddr*)&local_addr, local_len,
                                  (struct sockaddr*)&peer_addr, peer_len,
                                  now, user_conn);
        
        free(user_conn); // In real impl, manage lifecycle
    }
    xqc_engine_finish_recv(_engine);
}

void XquicSeastarServer::on_engine_timer_expire() {
    if (_engine) {
        xqc_engine_main_logic(_engine);
    }
}

// --- Trampolines ---

void XquicSeastarServer::ss_set_event_timer(xqc_msec_t wake_after, void *user_data) {
    auto* server = static_cast<XquicSeastarServer*>(user_data);
    if (server) {
        // Cancel existing timer and set new one
        server->_engine_timer.cancel();
        server->_engine_timer.arm(std::chrono::microseconds(wake_after));
    }
}

ssize_t XquicSeastarServer::ss_write_socket(const unsigned char *buf, size_t size, 
                                            const struct sockaddr *peer_addr, socklen_t peer_addrlen, 
                                            void *user_conn) {
    // This is tricky in Seastar because write_socket is synchronous in XQuic API,
    // but Seastar I/O is asynchronous.
    // Option 1: Use a blocking sendto (bad for performance)
    // Option 2: Queue the packet and flush later (complex)
    // Option 3: Use seastar::udp_channel::send() which returns future, but we can't await here.
    
    // For demo purposes, we will use a simple blocking sendto on the underlying FD
    // NOTE: This blocks the reactor thread! Not recommended for production high-load.
    // A better way is to store the server pointer in user_conn and use a non-blocking queue.
    
    int fd = -1;
    // We need access to the udp_channel's FD. 
    // Seastar doesn't expose FD easily. 
    // Alternative: Use raw socket created separately for sending if performance is critical.
    
    // Hack for demo: Retrieve FD from user_conn if we stored it, or use global/ref
    // Since we can't easily get the FD from udp_channel in a sync callback:
    // We will assume a simplified scenario where we might have stored the FD in user_conn
    // or we use a global reference to the channel (not ideal).
    
    // Let's assume we passed the server instance via user_conn (commented out above)
    // If not, we can't easily do async send here.
    
    // Fallback: Create a temporary socket to send (very inefficient, demo only)
    int sock = socket(peer_addr->sa_family, SOCK_DGRAM, 0);
    if (sock >= 0) {
        ssize_t n = sendto(sock, buf, size, 0, peer_addr, peer_addrlen);
        close(sock);
        return n;
    }
    return -1;
}

// Main entry point
int main(int argc, char** argv) {
    seastar::app_template app;
    app.add_options()
        ("port,p", bpo::value<uint16_t>()->default_value(8443), "Port to listen on")
        ("cert,c", bpo::value<std::string>()->default_value("./cert.crt"), "Cert file")
        ("key,k", bpo::value<std::string>()->default_value("./cert.key"), "Key file");

    return app.run_deprecated(argc, argv, [&app] {
        auto& config = app.configuration();
        uint16_t port = config["port"].as<uint16_t>();
        std::string cert = config["cert"].as<std::string>();
        std::string key = config["key"].as<std::string>();

        auto server = std::make_unique<XquicSeastarServer>();
        return server->start(port, cert, key).then([server = std::move(server)]() mutable {
            // Keep running until signal
            return seastar::make_ready_future<>();
        });
    });
}