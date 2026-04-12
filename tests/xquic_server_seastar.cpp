#include "xquic_server_seastar.hh"

#include "platform.h"
#include "user_conn.h"

#include <seastar/core/app-template.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>

#include <boost/program_options.hpp>

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <utility>

namespace bpo = boost::program_options;

namespace {

char kH3StatusName[] = ":status";
char kH3StatusValue[] = "200";
char kH3ContentLengthName[] = "content-length";
char kH3ContentLengthValue[] = "24";
char kH3ContentTypeName[] = "content-type";
char kH3ContentTypeValue[] = "text/plain";
unsigned char kH3ResponseBody[] = "Hello from Seastar XQUIC";

uint64_t xqc_now_us() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

void socket_address_to_sockaddr(const seastar::socket_address& src,
                                struct sockaddr_storage& dst, socklen_t& len) {
    std::memset(&dst, 0, sizeof(dst));
    if (src.family() == AF_INET) {
        std::memcpy(&dst, &src.as_posix_sockaddr_in(), sizeof(sockaddr_in));
        len = sizeof(sockaddr_in);
        return;
    }

    if (src.family() == AF_INET6) {
        std::memcpy(&dst, &src.as_posix_sockaddr_in6(), sizeof(sockaddr_in6));
        len = sizeof(sockaddr_in6);
        return;
    }

    throw std::invalid_argument("unsupported socket family");
}

} // namespace

XquicSeastarServer::XquicSeastarServer()
    : _engine_timer([this]() { on_engine_timer_expire(); })
    , _engine(nullptr)
    , _send_integration()
    , _port(0)
    , _stopping(false)
    , _send_flush_in_progress(false) {
}

XquicSeastarServer::~XquicSeastarServer() {
    if (_engine != nullptr) {
        xqc_engine_destroy(_engine);
        _engine = nullptr;
    }
}

void XquicSeastarServer::init_xquic_engine() {
    xqc_platform_init_env();

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        throw std::runtime_error("xqc_engine_get_default_config failed");
    }
    config.cfg_log_level = XQC_LOG_INFO;

    xqc_engine_ssl_config_t ssl_config;
    std::memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.cert_file = _cert_path.data();
    ssl_config.private_key_file = _key_path.data();
    ssl_config.ciphers = XQC_TLS_CIPHERS;
    ssl_config.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cb;
    std::memset(&engine_cb, 0, sizeof(engine_cb));
    engine_cb.set_event_timer = XquicSeastarServer::ss_set_event_timer;

    xqc_transport_callbacks_t transport_cbs;
    std::memset(&transport_cbs, 0, sizeof(transport_cbs));
    transport_cbs.write_socket = XquicSeastarServer::ss_write_socket;

    _engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl_config, &engine_cb, &transport_cbs, this);
    if (_engine == nullptr) {
        throw std::runtime_error("xqc_engine_create failed");
    }

    xqc_h3_callbacks_t h3_cbs;
    std::memset(&h3_cbs, 0, sizeof(h3_cbs));
    h3_cbs.h3c_cbs.h3_conn_create_notify = XquicSeastarServer::ss_h3_conn_create_notify;
    h3_cbs.h3c_cbs.h3_conn_close_notify = XquicSeastarServer::ss_h3_conn_close_notify;
    h3_cbs.h3r_cbs.h3_request_write_notify = XquicSeastarServer::ss_h3_request_write_notify;
    h3_cbs.h3r_cbs.h3_request_read_notify = XquicSeastarServer::ss_h3_request_read_notify;
    h3_cbs.h3r_cbs.h3_request_close_notify = XquicSeastarServer::ss_h3_request_close_notify;

    if (xqc_h3_ctx_init(_engine, &h3_cbs) != XQC_OK) {
        throw std::runtime_error("xqc_h3_ctx_init failed");
    }
}

seastar::future<> XquicSeastarServer::start(uint16_t port, const std::string& cert_path, const std::string& key_path) {
    try {
        _port = port;
        _cert_path = cert_path;
        _key_path = key_path;
        _stopping = false;
        _send_integration.clear();

        init_xquic_engine();

        seastar::socket_address bind_addr = seastar::make_ipv4_address(seastar::ipv4_addr(port));
        _udp_channel.emplace(seastar::engine().net().make_bound_datagram_channel(bind_addr));

        _receive_loop.emplace(
            seastar::with_gate(_background_ops, [this] {
                return run_receive_loop();
            }).handle_exception([this](std::exception_ptr ep) {
                if (_stopping) {
                    return seastar::make_ready_future<>();
                }
                return seastar::make_exception_future<>(ep);
            })
        );

        std::cout << "Seastar XQUIC server listening on UDP port " << _port << std::endl;
        return seastar::make_ready_future<>();

    } catch (...) {
        if (_udp_channel) {
            _udp_channel->close();
            _udp_channel.reset();
        }
        if (_engine != nullptr) {
            xqc_engine_destroy(_engine);
            _engine = nullptr;
        }
        return seastar::make_exception_future<>(std::current_exception());
    }
}

seastar::future<> XquicSeastarServer::stop() {
    if (_stopping) {
        return seastar::make_ready_future<>();
    }

    _stopping = true;
    _engine_timer.cancel();

    if (_udp_channel) {
        _udp_channel->shutdown_input();
        _udp_channel->shutdown_output();
    }

    seastar::future<> receive_loop = seastar::make_ready_future<>();
    if (_receive_loop.has_value()) {
        receive_loop = std::move(_receive_loop.value());
        _receive_loop.reset();
    }

    return std::move(receive_loop)
        .handle_exception([this](std::exception_ptr ep) {
            if (_stopping) {
                return seastar::make_ready_future<>();
            }
            return seastar::make_exception_future<>(ep);
        })
        .then([this] {
            return _background_ops.close();
        })
        .then([this] {
            _send_integration.clear();
            if (_udp_channel) {
                _udp_channel->close();
                _udp_channel.reset();
            }
            if (_engine != nullptr) {
                xqc_engine_destroy(_engine);
                _engine = nullptr;
            }
            return seastar::make_ready_future<>();
        });
}

seastar::future<> XquicSeastarServer::run_receive_loop() {
    return seastar::repeat([this]() {
        if (_stopping || !_udp_channel) {
            return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::yes);
        }

        return _udp_channel->receive().then([this](seastar::net::udp_datagram datagram) {
            on_datagram(datagram);
            return seastar::stop_iteration::no;
        }).handle_exception([this](std::exception_ptr ep) {
            if (_stopping) {
                return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::yes);
            }
            return seastar::make_exception_future<seastar::stop_iteration>(ep);
        });
    });
}

void XquicSeastarServer::on_datagram(seastar::net::udp_datagram& datagram) {
    if (_engine == nullptr) {
        return;
    }

    struct sockaddr_storage peer_addr;
    struct sockaddr_storage local_addr;
    socklen_t peer_len = 0;
    socklen_t local_len = 0;
    socket_address_to_sockaddr(datagram.get_src(), peer_addr, peer_len);
    socket_address_to_sockaddr(datagram.get_dst(), local_addr, local_len);

    user_conn_t user_conn;
    std::memset(&user_conn, 0, sizeof(user_conn));
    user_conn.server = this;

    seastar::net::packet& packet = datagram.get_data();
    for (auto& frag : packet.fragments()) {
        xqc_engine_packet_process(_engine,
                                  reinterpret_cast<const unsigned char*>(frag.base),
                                  frag.size,
                                  reinterpret_cast<struct sockaddr*>(&local_addr),
                                  local_len,
                                  reinterpret_cast<struct sockaddr*>(&peer_addr),
                                  peer_len,
                                  xqc_now_us(),
                                  &user_conn);
    }

    xqc_engine_finish_recv(_engine);
    schedule_send_flush();
}

void XquicSeastarServer::on_engine_timer_expire() {
    if (_engine != nullptr) {
        xqc_engine_main_logic(_engine);
        schedule_send_flush();
    }
}

ssize_t XquicSeastarServer::enqueue_send(const unsigned char *buf, size_t size,
                                         const struct sockaddr *peer_addr, socklen_t peer_addrlen) {
    if (_stopping || !_udp_channel) {
        errno = ESHUTDOWN;
        return -1;
    }

    ssize_t queued = _send_integration.enqueue_write(buf, size, peer_addr, peer_addrlen);
    if (queued < 0) {
        return -1;
    }

    try {
        schedule_send_flush();
        return queued;

    } catch (...) {
        errno = EINVAL;
        return -1;
    }
}

void XquicSeastarServer::schedule_send_flush() {
    if (_stopping || !_udp_channel || _send_flush_in_progress || _send_integration.empty()) {
        return;
    }

    _send_flush_in_progress = true;
    (void)seastar::with_gate(_background_ops, [this] {
        return flush_send_queue();
    }).handle_exception([this](std::exception_ptr ep) {
        try {
            std::rethrow_exception(ep);
        } catch (const std::exception& ex) {
            std::cerr << "Seastar send flush failed: " << ex.what() << std::endl;
        } catch (...) {
            std::cerr << "Seastar send flush failed with unknown exception" << std::endl;
        }
        _send_integration.clear();
        return seastar::make_ready_future<>();
    }).finally([this] {
        _send_flush_in_progress = false;
        if (!_stopping && !_send_integration.empty()) {
            schedule_send_flush();
        }
    });
}

seastar::future<> XquicSeastarServer::flush_send_queue() {
    if (_stopping || !_udp_channel) {
        return seastar::make_ready_future<>();
    }

    return _send_integration.flush_to(*_udp_channel);
}

void XquicSeastarServer::send_h3_response(user_stream_t *user_stream) {
    if (user_stream == nullptr || user_stream->h3_request == nullptr || user_stream->header_sent) {
        return;
    }

    xqc_http_header_t headers[] = {
        {
            {.iov_base = kH3StatusName, .iov_len = sizeof(kH3StatusName) - 1},
            {.iov_base = kH3StatusValue, .iov_len = sizeof(kH3StatusValue) - 1},
            0
        },
        {
            {.iov_base = kH3ContentLengthName, .iov_len = sizeof(kH3ContentLengthName) - 1},
            {.iov_base = kH3ContentLengthValue, .iov_len = sizeof(kH3ContentLengthValue) - 1},
            0
        },
        {
            {.iov_base = kH3ContentTypeName, .iov_len = sizeof(kH3ContentTypeName) - 1},
            {.iov_base = kH3ContentTypeValue, .iov_len = sizeof(kH3ContentTypeValue) - 1},
            0
        },
    };
    xqc_http_headers_t response_headers = {
        .headers = headers,
        .count = sizeof(headers) / sizeof(headers[0]),
    };

    user_stream->header_sent = 1;
    xqc_h3_request_send_headers(reinterpret_cast<xqc_h3_request_t*>(user_stream->h3_request), &response_headers, 0);
    xqc_h3_request_send_body(reinterpret_cast<xqc_h3_request_t*>(user_stream->h3_request),
                             kH3ResponseBody,
                             sizeof(kH3ResponseBody) - 1, 1);
}

int XquicSeastarServer::on_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    (void)cid;
    (void)user_data;

    user_conn_t *u_conn = static_cast<user_conn_t*>(std::calloc(1, sizeof(user_conn_t)));
    if (u_conn == nullptr) {
        return -1;
    }

    u_conn->server = this;
    u_conn->h3_conn = conn;
    xqc_h3_conn_set_user_data(conn, u_conn);
    return 0;
}

int XquicSeastarServer::on_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    (void)conn;
    (void)cid;
    std::free(user_data);
    return 0;
}

xqc_int_t XquicSeastarServer::on_h3_request_write_notify(xqc_h3_request_t *req, void *user_data) {
    (void)req;
    send_h3_response(static_cast<user_stream_t*>(user_data));
    return 0;
}

xqc_int_t XquicSeastarServer::on_h3_request_read_notify(xqc_h3_request_t *req,
                                                        xqc_request_notify_flag_t flag, void *user_data) {
    user_stream_t *user_stream = static_cast<user_stream_t*>(user_data);
    if (user_stream == nullptr) {
        user_stream = static_cast<user_stream_t*>(std::calloc(1, sizeof(user_stream_t)));
        if (user_stream == nullptr) {
            return -1;
        }
        user_stream->server = this;
        user_stream->h3_request = req;
        user_stream->is_h3 = 1;
        xqc_h3_request_set_user_data(req, user_stream);
    }

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(req, nullptr);
        if (headers != nullptr) {
            std::free(headers);
        }
    }

    bool should_respond = false;

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char body[4096];
        unsigned char fin = 0;
        while (true) {
            ssize_t read = xqc_h3_request_recv_body(req, body, sizeof(body), &fin);
            if (read <= 0) {
                break;
            }
            user_stream->total_recvd += static_cast<size_t>(read);
            if (fin) {
                should_respond = true;
                break;
            }
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        should_respond = true;
    }

    if (should_respond) {
        send_h3_response(user_stream);
    }

    return 0;
}

xqc_int_t XquicSeastarServer::on_h3_request_close_notify(xqc_h3_request_t *req, void *user_data) {
    (void)req;
    std::free(user_data);
    return 0;
}

void XquicSeastarServer::ss_set_event_timer(xqc_msec_t wake_after, void *user_data) {
    auto* server = static_cast<XquicSeastarServer*>(user_data);
    if (server == nullptr) {
        return;
    }

    server->_engine_timer.cancel();
    server->_engine_timer.arm(std::chrono::milliseconds(wake_after));
}

ssize_t XquicSeastarServer::ss_write_socket(const unsigned char *buf, size_t size,
                                            const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                                            void *user_conn) {
    auto* u_conn = static_cast<user_conn_t*>(user_conn);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    if (server == nullptr) {
        errno = EINVAL;
        return -1;
    }

    return server->enqueue_send(buf, size, peer_addr, peer_addrlen);
}

int XquicSeastarServer::ss_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    auto* server = static_cast<XquicSeastarServer*>(user_data);
    return server == nullptr ? -1 : server->on_h3_conn_create_notify(conn, cid, nullptr);
}

int XquicSeastarServer::ss_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    return server == nullptr ? 0 : server->on_h3_conn_close_notify(conn, cid, user_data);
}

xqc_int_t XquicSeastarServer::ss_h3_request_write_notify(xqc_h3_request_t *req, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    return server == nullptr ? 0 : server->on_h3_request_write_notify(req, user_data);
}

xqc_int_t XquicSeastarServer::ss_h3_request_read_notify(xqc_h3_request_t *req,
                                                        xqc_request_notify_flag_t flag, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;

    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_h3_get_conn_user_data_by_request(req));
        if (u_conn != nullptr) {
            server = static_cast<XquicSeastarServer*>(u_conn->server);
        }
    }

    return server == nullptr ? -1 : server->on_h3_request_read_notify(req, flag, user_data);
}

xqc_int_t XquicSeastarServer::ss_h3_request_close_notify(xqc_h3_request_t *req, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    return server == nullptr ? 0 : server->on_h3_request_close_notify(req, user_data);
}

int main(int argc, char **argv) {
    seastar::app_template app;
    app.add_options()
        ("port,p", bpo::value<uint16_t>()->default_value(8443), "UDP port")
        ("cert,c", bpo::value<std::string>()->default_value("./server.crt"), "TLS certificate path")
        ("key,k", bpo::value<std::string>()->default_value("./server.key"), "TLS private key path");

    return app.run_deprecated(argc, argv, [&app] {
        auto& config = app.configuration();
        auto server = std::make_unique<XquicSeastarServer>();

        return server->start(config["port"].as<uint16_t>(),
                             config["cert"].as<std::string>(),
                             config["key"].as<std::string>())
            .then([server = std::move(server)]() mutable {
                // Keep the sample server alive until the Seastar app shuts down.
                return seastar::keep_doing([] {
                        return seastar::sleep(std::chrono::hours(24));
                    })
                    .finally([server = std::move(server)]() mutable {
                        return server->stop();
                    });
            });
    });
}
