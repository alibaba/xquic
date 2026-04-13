#include "xquic_server_seastar.hh"

#include "platform.h"
#include "user_conn.h"

#include <algorithm>
#include <seastar/core/app-template.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>

#include <boost/program_options.hpp>

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <new>
#include <stdexcept>
#include <utility>

namespace bpo = boost::program_options;

namespace {

using XqcHeadersPtr = std::unique_ptr<xqc_http_headers_t, decltype(&std::free)>;
constexpr char kTransportAlpn[] = "transport";
constexpr size_t kTransportPreviewLimit = 96;
constexpr size_t kTransportFrameHeaderLen = 5;

enum TransportDemoFrameType : uint8_t {
    XQC_TRANSPORT_DEMO_FRAME_HELLO = 0x01,
    XQC_TRANSPORT_DEMO_FRAME_MESSAGE = 0x02,
    XQC_TRANSPORT_DEMO_FRAME_METADATA = 0x03,
    XQC_TRANSPORT_DEMO_FRAME_STATUS = 0x80,
    XQC_TRANSPORT_DEMO_FRAME_RESULT = 0x81,
    XQC_TRANSPORT_DEMO_FRAME_INFO = 0x82,
    XQC_TRANSPORT_DEMO_FRAME_ERROR = 0xff,
};

struct TransportDemoRequest {
    bool has_message = false;
    size_t frame_count = 0;
    std::string hello;
    std::string message;
    std::string metadata;
    std::string error;
};

const char kH3StatusName[] = ":status";
const char kH3StatusValue[] = "200";
const char kH3ContentLengthName[] = "content-length";
const char kH3ContentLengthValue[] = "24";
const char kH3ContentTypeName[] = "content-type";
const char kH3ContentTypeValue[] = "text/plain";
const unsigned char kH3ResponseBody[] = "Hello from Seastar XQUIC";

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

bool copy_conn_address(xqc_connection_t *conn, user_conn_t *user_conn, bool peer) {
    auto addr = std::unique_ptr<sockaddr_storage, decltype(&std::free)>(
        static_cast<sockaddr_storage*>(std::calloc(1, sizeof(sockaddr_storage))), &std::free);
    if (!addr) {
        return false;
    }

    socklen_t addr_len = 0;
    xqc_int_t ret = peer
        ? xqc_conn_get_peer_addr(conn, reinterpret_cast<sockaddr*>(addr.get()), sizeof(sockaddr_storage), &addr_len)
        : xqc_conn_get_local_addr(conn, reinterpret_cast<sockaddr*>(addr.get()), sizeof(sockaddr_storage), &addr_len);
    if (ret != XQC_OK) {
        return false;
    }

    if (peer) {
        std::free(user_conn->peer_addr);
        user_conn->peer_addr = reinterpret_cast<sockaddr*>(addr.release());
        user_conn->peer_addrlen = addr_len;
    } else {
        std::free(user_conn->local_addr);
        user_conn->local_addr = reinterpret_cast<sockaddr*>(addr.release());
        user_conn->local_addrlen = addr_len;
    }

    return true;
}

void release_user_conn(user_conn_t *user_conn) {
    if (user_conn == nullptr) {
        return;
    }

    std::free(user_conn->peer_addr);
    user_conn->peer_addr = nullptr;
    user_conn->peer_addrlen = 0;
    std::free(user_conn->local_addr);
    user_conn->local_addr = nullptr;
    user_conn->local_addrlen = 0;
}

void release_user_stream(user_stream_t *user_stream) {
    if (user_stream == nullptr) {
        return;
    }

    std::free(user_stream->send_body);
    user_stream->send_body = nullptr;
    user_stream->send_body_len = 0;
    user_stream->send_offset = 0;
    std::free(user_stream->recv_body);
    user_stream->recv_body = nullptr;
    user_stream->recv_body_len = 0;
    user_stream->recv_body_cap = 0;
    if (user_stream->recv_body_fp != nullptr) {
        std::fclose(user_stream->recv_body_fp);
        user_stream->recv_body_fp = nullptr;
    }
}

std::string format_socket_address(const sockaddr *addr, socklen_t addr_len) {
    if (addr == nullptr) {
        return "unknown";
    }

    char host[INET6_ADDRSTRLEN] = {0};
    uint16_t port = 0;
    if (addr->sa_family == AF_INET && addr_len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto *addr4 = reinterpret_cast<const sockaddr_in*>(addr);
        if (inet_ntop(AF_INET, &addr4->sin_addr, host, sizeof(host)) == nullptr) {
            return "unknown";
        }
        port = ntohs(addr4->sin_port);

    } else if (addr->sa_family == AF_INET6 && addr_len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto *addr6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, host, sizeof(host)) == nullptr) {
            return "unknown";
        }
        port = ntohs(addr6->sin6_port);

    } else {
        return "unknown";
    }

    return std::string(host) + ":" + std::to_string(port);
}

std::string preview_transport_payload(const char *data, size_t len) {
    if (data == nullptr || len == 0) {
        return "<empty>";
    }

    const size_t preview_len = std::min(len, kTransportPreviewLimit);
    std::string preview;
    preview.reserve(preview_len + 3);
    for (size_t i = 0; i < preview_len; ++i) {
        const unsigned char ch = static_cast<unsigned char>(data[i]);
        preview.push_back(std::isprint(ch) != 0 ? static_cast<char>(ch) : '.');
    }
    if (len > preview_len) {
        preview += "...";
    }
    return preview;
}

bool ensure_stream_recv_capacity(user_stream_t *user_stream, size_t extra_len) {
    if (user_stream->recv_body_len + extra_len <= user_stream->recv_body_cap) {
        return true;
    }

    size_t new_cap = user_stream->recv_body_cap == 0 ? 4096 : user_stream->recv_body_cap;
    while (new_cap < user_stream->recv_body_len + extra_len) {
        new_cap = std::max(new_cap * 2, user_stream->recv_body_len + extra_len);
    }

    void *new_buf = std::realloc(user_stream->recv_body, new_cap);
    if (new_buf == nullptr) {
        return false;
    }

    user_stream->recv_body = static_cast<char*>(new_buf);
    user_stream->recv_body_cap = new_cap;
    return true;
}

bool append_stream_payload(user_stream_t *user_stream, const unsigned char *data, size_t data_len) {
    if (!ensure_stream_recv_capacity(user_stream, data_len)) {
        return false;
    }

    std::memcpy(user_stream->recv_body + user_stream->recv_body_len, data, data_len);
    user_stream->recv_body_len += data_len;
    return true;
}

uint32_t read_u32_be(const unsigned char *data) {
    return (static_cast<uint32_t>(data[0]) << 24)
        | (static_cast<uint32_t>(data[1]) << 16)
        | (static_cast<uint32_t>(data[2]) << 8)
        | static_cast<uint32_t>(data[3]);
}

void append_u32_be(std::string& out, uint32_t value) {
    out.push_back(static_cast<char>((value >> 24) & 0xff));
    out.push_back(static_cast<char>((value >> 16) & 0xff));
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>(value & 0xff));
}

void append_transport_frame(std::string& out, uint8_t type, const char *data, size_t len) {
    out.push_back(static_cast<char>(type));
    append_u32_be(out, static_cast<uint32_t>(len));
    if (len > 0) {
        out.append(data, len);
    }
}

void append_transport_frame(std::string& out, uint8_t type, const std::string& payload) {
    append_transport_frame(out, type, payload.data(), payload.size());
}

bool parse_transport_demo_request(const char *data, size_t len, TransportDemoRequest& request) {
    size_t offset = 0;
    while (offset < len) {
        if (len - offset < kTransportFrameHeaderLen) {
            request.error = "incomplete frame header";
            return false;
        }

        const uint8_t type = static_cast<uint8_t>(data[offset]);
        const uint32_t payload_len = read_u32_be(reinterpret_cast<const unsigned char*>(data + offset + 1));
        offset += kTransportFrameHeaderLen;
        if (len - offset < payload_len) {
            request.error = "truncated frame payload";
            return false;
        }

        const char *payload = data + offset;
        request.frame_count++;
        switch (type) {
        case XQC_TRANSPORT_DEMO_FRAME_HELLO:
            request.hello.assign(payload, payload_len);
            break;
        case XQC_TRANSPORT_DEMO_FRAME_MESSAGE:
            request.message.append(payload, payload_len);
            request.has_message = true;
            break;
        case XQC_TRANSPORT_DEMO_FRAME_METADATA:
            request.metadata.append(payload, payload_len);
            break;
        default:
            request.error = "unknown frame type: " + std::to_string(type);
            return false;
        }

        offset += payload_len;
    }

    if (!request.has_message) {
        request.error = "missing MESSAGE frame";
        return false;
    }

    return true;
}

bool build_transport_demo_response(xqc_stream_t *stream, user_stream_t *user_stream) {
    if (stream == nullptr || user_stream == nullptr || user_stream->user_conn == nullptr) {
        return false;
    }

    TransportDemoRequest request;
    const bool parse_ok = parse_transport_demo_request(user_stream->recv_body, user_stream->recv_body_len, request);
    const std::string peer = format_socket_address(user_stream->user_conn->peer_addr, user_stream->user_conn->peer_addrlen);
    const std::string local = format_socket_address(user_stream->user_conn->local_addr, user_stream->user_conn->local_addrlen);
    const std::string preview = preview_transport_payload(
        parse_ok ? request.message.data() : user_stream->recv_body,
        parse_ok ? request.message.size() : user_stream->recv_body_len);
    std::string response;
    append_transport_frame(response,
        parse_ok ? XQC_TRANSPORT_DEMO_FRAME_STATUS : XQC_TRANSPORT_DEMO_FRAME_ERROR,
        parse_ok ? std::string("ok") : request.error);

    const std::string result =
        "stream_id=" + std::to_string(xqc_stream_id(stream)) + "\n"
        "peer=" + peer + "\n"
        "local=" + local + "\n"
        "request_bytes=" + std::to_string(user_stream->recv_body_len) + "\n"
        "request_frames=" + std::to_string(request.frame_count) + "\n"
        "hello=" + (request.hello.empty() ? std::string("<none>") : request.hello) + "\n"
        "metadata=" + (request.metadata.empty() ? std::string("<none>") : request.metadata) + "\n";
    append_transport_frame(response, XQC_TRANSPORT_DEMO_FRAME_INFO, result);

    const std::string message_payload = parse_ok ? preview : "request rejected";
    append_transport_frame(response, XQC_TRANSPORT_DEMO_FRAME_RESULT, message_payload);

    auto buffer = std::unique_ptr<char, decltype(&std::free)>(
        static_cast<char*>(std::malloc(response.size())), &std::free);
    if (buffer == nullptr) {
        return false;
    }

    std::memcpy(buffer.get(), response.data(), response.size());
    std::free(user_stream->send_body);
    user_stream->send_body = buffer.release();
    user_stream->send_body_len = response.size();
    user_stream->send_offset = 0;
    return true;
}

} // namespace

XquicSeastarServer::XquicSeastarServer()
    : _engine_timer([this]() { on_engine_timer_expire(); })
    , _engine(nullptr)
    , _send_integration()
    , _packet_user_conn()
    , _port(0)
    , _stopping(false)
    , _send_flush_in_progress(false) {
    _packet_user_conn.server = this;
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
    transport_cbs.server_accept = XquicSeastarServer::ss_server_accept;
    transport_cbs.write_socket = XquicSeastarServer::ss_write_socket;
    transport_cbs.conn_update_cid_notify = XquicSeastarServer::ss_conn_update_cid_notify;

    _engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl_config, &engine_cb, &transport_cbs, this);
    if (_engine == nullptr) {
        throw std::runtime_error("xqc_engine_create failed");
    }

    xqc_app_proto_callbacks_t transport_ap_cbs;
    std::memset(&transport_ap_cbs, 0, sizeof(transport_ap_cbs));
    transport_ap_cbs.conn_cbs.conn_create_notify = XquicSeastarServer::ss_conn_create_notify;
    transport_ap_cbs.conn_cbs.conn_close_notify = XquicSeastarServer::ss_conn_close_notify;
    transport_ap_cbs.stream_cbs.stream_create_notify = XquicSeastarServer::ss_stream_create_notify;
    transport_ap_cbs.stream_cbs.stream_write_notify = XquicSeastarServer::ss_stream_write_notify;
    transport_ap_cbs.stream_cbs.stream_read_notify = XquicSeastarServer::ss_stream_read_notify;
    transport_ap_cbs.stream_cbs.stream_close_notify = XquicSeastarServer::ss_stream_close_notify;
    if (xqc_engine_register_alpn(_engine, kTransportAlpn, sizeof(kTransportAlpn) - 1, &transport_ap_cbs, nullptr) != XQC_OK) {
        throw std::runtime_error("xqc_engine_register_alpn failed");
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
        _packet_user_conn = {.server = this};

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
                                  &_packet_user_conn);
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

int XquicSeastarServer::on_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                                         const xqc_cid_t *cid, void *user_data) {
    (void)engine;
    (void)user_data;

    try {
        auto u_conn = std::make_unique<user_conn_t>();
        u_conn->server = this;
        if (cid != nullptr) {
            u_conn->cid = *cid;
        }
        if (!copy_conn_address(conn, u_conn.get(), true) || !copy_conn_address(conn, u_conn.get(), false)) {
            release_user_conn(u_conn.get());
            return -1;
        }
        xqc_conn_set_transport_user_data(conn, u_conn.release());
        return 0;

    } catch (const std::bad_alloc&) {
        return -1;
    }
}

void XquicSeastarServer::on_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                                                   const xqc_cid_t *new_cid, void *user_data) {
    (void)conn;
    (void)retire_cid;

    auto *u_conn = static_cast<user_conn_t*>(user_data);
    if (u_conn != nullptr && new_cid != nullptr) {
        u_conn->cid = *new_cid;
    }
}

int XquicSeastarServer::on_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                              void *user_data, void *conn_proto_data) {
    (void)conn;
    (void)conn_proto_data;

    auto *u_conn = static_cast<user_conn_t*>(user_data);
    if (u_conn == nullptr) {
        return -1;
    }

    if (cid != nullptr) {
        u_conn->cid = *cid;
    }
    return 0;
}

int XquicSeastarServer::on_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                             void *user_data, void *conn_proto_data) {
    (void)conn;
    (void)cid;
    (void)conn_proto_data;

    auto u_conn = std::unique_ptr<user_conn_t>(static_cast<user_conn_t*>(user_data));
    release_user_conn(u_conn.get());
    return 0;
}

xqc_int_t XquicSeastarServer::on_stream_write_notify(xqc_stream_t *stream, void *user_data) {
    user_stream_t *user_stream = static_cast<user_stream_t*>(user_data);
    if (stream == nullptr || user_stream == nullptr || user_stream->send_body == nullptr) {
        return 0;
    }

    while (user_stream->send_offset < user_stream->send_body_len) {
        const size_t remaining = user_stream->send_body_len - user_stream->send_offset;
        const ssize_t sent = xqc_stream_send(stream,
            reinterpret_cast<unsigned char*>(user_stream->send_body + user_stream->send_offset), remaining, 1);
        if (sent == -XQC_EAGAIN) {
            return 0;
        }
        if (sent < 0) {
            return -1;
        }

        user_stream->send_offset += static_cast<size_t>(sent);
        user_stream->total_sent += static_cast<size_t>(sent);
    }

    return 0;
}

xqc_int_t XquicSeastarServer::on_stream_create_notify(xqc_stream_t *stream, void *user_data) {
    (void)user_data;
    try {
        auto owned_stream = std::make_unique<user_stream_t>();
        owned_stream->server = this;
        owned_stream->stream = stream;
        owned_stream->user_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        xqc_stream_set_user_data(stream, owned_stream.get());
        owned_stream.release();
        return 0;

    } catch (const std::bad_alloc&) {
        return -1;
    }
}

xqc_int_t XquicSeastarServer::on_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    user_stream_t *user_stream = static_cast<user_stream_t*>(user_data);
    if (stream == nullptr || user_stream == nullptr) {
        return -1;
    }

    unsigned char body[4096];
    unsigned char fin = 0;
    while (true) {
        ssize_t read = xqc_stream_recv(stream, body, sizeof(body), &fin);
        if (read == -XQC_EAGAIN || read == 0) {
            break;
        }
        if (read < 0) {
            return -1;
        }

        user_stream->total_recvd += static_cast<size_t>(read);
        if (!append_stream_payload(user_stream, body, static_cast<size_t>(read))) {
            return -1;
        }
        if (fin) {
            user_stream->recv_fin = 1;
        }
    }

    if (!user_stream->recv_fin) {
        return 0;
    }

    if (user_stream->send_body == nullptr && !build_transport_demo_response(stream, user_stream)) {
        return -1;
    }

    return on_stream_write_notify(stream, user_stream);
}

xqc_int_t XquicSeastarServer::on_stream_close_notify(xqc_stream_t *stream, void *user_data) {
    (void)stream;

    auto user_stream = std::unique_ptr<user_stream_t>(static_cast<user_stream_t*>(user_data));
    release_user_stream(user_stream.get());
    return 0;
}

int XquicSeastarServer::on_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    auto *u_conn = static_cast<user_conn_t*>(user_data);
    if (u_conn == nullptr) {
        return -1;
    }

    u_conn->h3 = 1;
    u_conn->h3_conn = conn;
    if (cid != nullptr) {
        u_conn->cid = *cid;
    }
    xqc_h3_conn_set_user_data(conn, u_conn);
    return 0;
}

int XquicSeastarServer::on_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    (void)conn;
    (void)cid;
    auto u_conn = std::unique_ptr<user_conn_t>(static_cast<user_conn_t*>(user_data));
    release_user_conn(u_conn.get());
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
        try {
            auto owned_stream = std::make_unique<user_stream_t>();
            owned_stream->server = this;
            owned_stream->h3_request = req;
            owned_stream->is_h3 = 1;
            user_stream = owned_stream.get();
            xqc_h3_request_set_user_data(req, user_stream);
            owned_stream.release();

        } catch (const std::bad_alloc&) {
            return -1;
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        XqcHeadersPtr headers(xqc_h3_request_recv_headers(req, nullptr), &std::free);
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
    auto user_stream = std::unique_ptr<user_stream_t>(static_cast<user_stream_t*>(user_data));
    release_user_stream(user_stream.get());
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

int XquicSeastarServer::ss_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                                         const xqc_cid_t *cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    return server == nullptr ? -1 : server->on_server_accept(engine, conn, cid, user_data);
}

void XquicSeastarServer::ss_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                                                   const xqc_cid_t *new_cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    if (server != nullptr) {
        server->on_conn_update_cid_notify(conn, retire_cid, new_cid, user_data);
    }
}

int XquicSeastarServer::ss_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                              void *user_data, void *conn_proto_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    return server == nullptr ? -1 : server->on_conn_create_notify(conn, cid, user_data, conn_proto_data);
}

int XquicSeastarServer::ss_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                                             void *user_data, void *conn_proto_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    return server == nullptr ? 0 : server->on_conn_close_notify(conn, cid, user_data, conn_proto_data);
}

xqc_int_t XquicSeastarServer::ss_stream_write_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) {
            server = static_cast<XquicSeastarServer*>(u_conn->server);
        }
    }
    return server == nullptr ? -1 : server->on_stream_write_notify(stream, user_data);
}

xqc_int_t XquicSeastarServer::ss_stream_create_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) {
            server = static_cast<XquicSeastarServer*>(u_conn->server);
        }
    }
    return server == nullptr ? -1 : server->on_stream_create_notify(stream, user_data);
}

xqc_int_t XquicSeastarServer::ss_stream_read_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) {
            server = static_cast<XquicSeastarServer*>(u_conn->server);
        }
    }
    return server == nullptr ? -1 : server->on_stream_read_notify(stream, user_data);
}

xqc_int_t XquicSeastarServer::ss_stream_close_notify(xqc_stream_t *stream, void *user_data) {
    auto* user_stream = static_cast<user_stream_t*>(user_data);
    auto* server = (user_stream != nullptr) ? static_cast<XquicSeastarServer*>(user_stream->server) : nullptr;
    if (server == nullptr) {
        auto* u_conn = static_cast<user_conn_t*>(xqc_get_conn_user_data_by_stream(stream));
        if (u_conn != nullptr) {
            server = static_cast<XquicSeastarServer*>(u_conn->server);
        }
    }
    return server == nullptr ? 0 : server->on_stream_close_notify(stream, user_data);
}

int XquicSeastarServer::ss_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data) {
    auto* u_conn = static_cast<user_conn_t*>(user_data);
    auto* server = (u_conn != nullptr) ? static_cast<XquicSeastarServer*>(u_conn->server) : nullptr;
    return server == nullptr ? -1 : server->on_h3_conn_create_notify(conn, cid, user_data);
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
