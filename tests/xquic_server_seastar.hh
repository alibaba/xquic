#pragma once

#include <seastar/core/seastar.hh>
#include <seastar/core/app-template.hh>
#include <seastar/net/udp.hh>
#include <seastar/core/timer.hh>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <memory>
#include <cstring>
#include <iostream>

// Forward declarations
struct user_conn_t;
struct user_stream_t;

class XquicSeastarServer {
public:
    XquicSeastarServer();
    ~XquicSeastarServer();

    seastar::future<> start(uint16_t port, const std::string& cert_path, const std::string& key_path);
    seastar::future<> stop();

private:
    // Seastar components
    std::unique_ptr<seastar::udp_channel> _udp_channel;
    seastar::timer<> _engine_timer;
    
    // XQuic components
    xqc_engine_t* _engine;
    
    // Configuration
    std::string _cert_path;
    std::string _key_path;

    // Callbacks handlers
    void on_packet_received(seastar::net::packet pkt, seastar::socket_address addr);
    void on_engine_timer_expire();
    
    // XQuic Trampolines (Static methods to bridge C callbacks to this instance)
    static void ss_set_event_timer(xqc_msec_t wake_after, void *user_data);
    static ssize_t ss_write_socket(const unsigned char *buf, size_t size, 
                                   const struct sockaddr *peer_addr, socklen_t peer_addrlen, 
                                   void *user_conn);
    
    // Internal logic
    void init_xquic_engine();
};