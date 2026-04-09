#ifndef CLIENT_CTX_H
#define CLIENT_CTX_H

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations for types used in client_ctx_t
struct xqc_engine_s;
struct event;

// Minimal client_ctx_t definition for cross C/C++ use
// Only fields needed for trampoline/instance forwarding are included
// Add more fields as needed for migration

typedef struct client_ctx_s {
    struct xqc_engine_s   *engine;
    struct event          *ev_engine;
    int                    log_fd;
    int                    keylog_fd;
    struct event          *ev_delay;
    void                  *owner; // Opaque pointer to XquicClient instance
} client_ctx_t;

#ifdef __cplusplus
}
#endif

#endif // CLIENT_CTX_H
