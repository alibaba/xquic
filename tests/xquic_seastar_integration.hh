#pragma once

#include "xquic_seastar_queue.hh"

#include <seastar/core/future.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/api.hh>

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>

class XquicSeastarSendIntegration {
public:
    explicit XquicSeastarSendIntegration(size_t queue_capacity = XquicSeastarSendQueue::kDefaultCapacity)
        : _queue(queue_capacity) {
    }

    void clear() {
        _queue.clear();
    }

    bool empty() const {
        return _queue.empty();
    }

    ssize_t enqueue_write(const unsigned char *buf, size_t size,
                          const struct sockaddr *peer_addr, socklen_t peer_addrlen) {
        if (_queue.full()) {
            errno = EAGAIN;
            return -1;
        }

        try {
            if (!_queue.push(sockaddr_to_socket_address(peer_addr, peer_addrlen), buf, size)) {
                errno = EINVAL;
                return -1;
            }
            return static_cast<ssize_t>(size);

        } catch (const std::bad_alloc&) {
            errno = ENOMEM;
            return -1;

        } catch (...) {
            errno = EINVAL;
            return -1;
        }
    }

    seastar::future<> flush_to(seastar::net::udp_channel& udp_channel) {
        return seastar::do_until([this] {
            return _queue.empty();
        }, [this, &udp_channel] {
            XquicSeastarSendQueue::Datagram datagram = _queue.pop();
            seastar::temporary_buffer<char> buffer(datagram.payload.size());
            if (!datagram.payload.empty()) {
                std::memcpy(buffer.get_write(), datagram.payload.data(), datagram.payload.size());
            }
            return udp_channel.send(datagram.peer, seastar::net::packet(std::move(buffer)));
        });
    }

private:
    static seastar::socket_address sockaddr_to_socket_address(const struct sockaddr *addr, socklen_t len) {
        if (addr == nullptr) {
            throw std::invalid_argument("null sockaddr");
        }

        if (addr->sa_family == AF_INET) {
            if (len < static_cast<socklen_t>(sizeof(sockaddr_in))) {
                throw std::invalid_argument("invalid sockaddr_in length");
            }
            return seastar::socket_address(*reinterpret_cast<const sockaddr_in*>(addr));
        }

        if (addr->sa_family == AF_INET6) {
            if (len < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
                throw std::invalid_argument("invalid sockaddr_in6 length");
            }
            return seastar::socket_address(*reinterpret_cast<const sockaddr_in6*>(addr));
        }

        throw std::invalid_argument("unsupported sockaddr family");
    }

    XquicSeastarSendQueue _queue;
};
