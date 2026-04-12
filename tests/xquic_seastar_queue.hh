#pragma once

#include <seastar/net/api.hh>
#include <cstddef>
#include <deque>
#include <utility>
#include <vector>

class XquicSeastarSendQueue {
public:
    struct Datagram {
        seastar::socket_address peer;
        std::vector<unsigned char> payload;
    };

    explicit XquicSeastarSendQueue(size_t capacity = 1024)
        : _capacity(capacity) {
    }

    bool empty() const {
        return _queue.empty();
    }

    bool full() const {
        return _queue.size() >= _capacity;
    }

    size_t size() const {
        return _queue.size();
    }

    void clear() {
        _queue.clear();
    }

    bool push(seastar::socket_address peer, const unsigned char *payload, size_t payload_len) {
        if (full()) {
            return false;
        }

        if (payload == nullptr && payload_len != 0) {
            return false;
        }

        std::vector<unsigned char> payload_copy;
        if (payload_len != 0) {
            payload_copy.assign(payload, payload + payload_len);
        }

        _queue.push_back(Datagram{
            std::move(peer),
            std::move(payload_copy),
        });
        return true;
    }

    Datagram pop() {
        Datagram datagram = std::move(_queue.front());
        _queue.pop_front();
        return datagram;
    }

private:
    size_t _capacity;
    std::deque<Datagram> _queue;
};
