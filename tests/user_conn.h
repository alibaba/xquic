// tests/user_conn.h

#ifndef USER_CONN_H
#define USER_CONN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/socket.h>
#include <stdio.h>
#include <xquic/xquic_typedef.h>

// Forward declarations
struct event;
struct user_conn_s;

typedef struct user_stream_s {
    void* stream;           // xqc_stream_t* or xqc_h3_request_t*
    void* h3_request;       // Specifically for H3 request handle
    
    // Pointers to parent objects (void* to avoid C++ dependency in header)
    void* server;           // Pointer to XquicServer
    void* client;           // Pointer to XquicClient
    struct user_conn_s* user_conn; // Pointer to parent connection
    
    int is_h3;              // Flag to distinguish transport vs H3 stream
    
    // Timing & Stats
    uint64_t start_time;    
    size_t total_recvd;
    size_t total_sent;
    
    // Sending Data (Client/Server)
    char* send_body;
    size_t send_body_len;
    size_t send_offset;
    size_t send_body_max;
    
    // Receiving Data (Client mostly)
    char* recv_body;        // Buffer for received body (for echo check)
    size_t recv_body_len;   // Length of received body so far
    FILE* recv_body_fp;     // File pointer for saving received body
    int recv_fin;           // Flag indicating if FIN has been received
    
    // Header tracking
    int header_sent;
    int header_recvd;

} user_stream_t;

typedef struct user_conn_s {
    void* server;           // Pointer to XquicServer
    void* client;           // Pointer to XquicClient
    
    int socket;             // Socket file descriptor (alias for fd)
    int fd;                 // Socket file descriptor (used by client)
    
    // Event loop handles
    struct event* ev_socket;
    struct event* ev_timeout;
    
    // Address info
    struct sockaddr* peer_addr;
    socklen_t peer_addrlen;
    struct sockaddr* local_addr;
    socklen_t local_addrlen;
    int get_local_addr;     // Flag to track if local addr has been retrieved
    
    // Connection ID
    xqc_cid_t cid;
    
    // H3 specific
    void* h3_conn;          // xqc_h3_conn_t*
    int h3;                 // Flag indicating if this connection is using H3
} user_conn_t;

#ifdef __cplusplus
}
#endif

#endif // USER_CONN_H