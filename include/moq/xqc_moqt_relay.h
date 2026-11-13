/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef _XQC_MOQT_RELAY_H_INCLUDED_
#define _XQC_MOQT_RELAY_H_INCLUDED_

#include <moq/xqc_moqt.h>
#ifdef XQC_ENABLE_WEBTRANSPORT
#include <moq/xqc_moqt_webtransport.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xqc_moqt_relay_s xqc_moqt_relay_t;
typedef struct xqc_moqt_relay_peer_s xqc_moqt_relay_peer_t;

typedef struct {
    size_t        max_peers;
    size_t        max_requests;
    size_t        max_streams;
    size_t        max_bytes;
    xqc_usec_t    timeout;
} xqc_moqt_relay_config_t;

typedef struct {
    size_t      peers;
    size_t      requests;
    size_t      streams;
    size_t      bytes;
    uint64_t    forwarded;
    uint64_t    duplicates;
    uint64_t    expired;
    uint64_t    rejected;
    uint64_t    slow_subscribers;
    uint64_t    malformed;
    uint64_t    timeouts;
} xqc_moqt_relay_stats_t;

typedef struct {
    /* Required: validate SETUP against the peer's application-owned scope. */
    uint64_t  (*on_setup)(xqc_moqt_relay_peer_t *peer,
        const xqc_moqt_setup_t *setup, void *peer_data);
    /* Required: namespace publication and track access are separate grants. */
    xqc_int_t (*on_authorize)(xqc_moqt_relay_peer_t *peer,
        const xqc_moqt_message_t *message,
        const xqc_moqt_message_t *candidate, uint64_t *error, void *peer_data);
    /*
     * Required per-hop policy, including authorization of each outbound Track
     * and the publisher's shared all-prefix St. Incoming tokens are removed.
     * It may insert destination credentials in increasing parameter order;
     * views must survive until the next callback. Returning XQC_ERROR
     * prevents this upstream request.
     */
    xqc_int_t (*on_forward)(xqc_moqt_relay_peer_t *destination,
        xqc_moqt_message_t *message, void *peer_data);
    void      (*on_closed)(xqc_moqt_relay_peer_t *peer, uint64_t error,
        void *peer_data);
} xqc_moqt_relay_callbacks_t;

XQC_EXPORT_PUBLIC_API
void xqc_moqt_relay_config_init(xqc_moqt_relay_config_t *config);

XQC_EXPORT_PUBLIC_API
xqc_moqt_relay_t *xqc_moqt_relay_create(
    const xqc_moqt_relay_config_t *config,
    const xqc_moqt_relay_callbacks_t *callbacks);

/* Destroy peers first, outside all protocol/policy callbacks. */
XQC_EXPORT_PUBLIC_API
void xqc_moqt_relay_destroy(xqc_moqt_relay_t *relay);

/*
 * Called in connection creation. Scope is copied and matched as opaque bytes;
 * the application normalizes authority/path and checks SETUP accordingly.
 * Start peer_session() at handshake completion, destroy at connection close.
 */
XQC_EXPORT_PUBLIC_API
xqc_moqt_relay_peer_t *xqc_moqt_relay_peer_create(xqc_moqt_relay_t *relay,
    xqc_connection_t *connection, const xqc_moqt_config_t *config,
    const struct iovec *scope, void *peer_data);

#ifdef XQC_ENABLE_WEBTRANSPORT
/*
 * Same scope, policy, and bounds as a native peer. Bind at WT ready after
 * CONNECT authorization and moqt-22 selection; start peer_session() there.
 * Destroy the peer at WT close before H3 teardown. The endpoint WT
 * constructor's transport and SETUP restrictions also apply.
 */
XQC_EXPORT_PUBLIC_API
xqc_moqt_relay_peer_t *xqc_moqt_relay_peer_create_webtransport(
    xqc_moqt_relay_t *relay, xqc_wt_session_t *transport,
    const xqc_moqt_config_t *config, const struct iovec *scope, void *peer_data);
#endif

XQC_EXPORT_PUBLIC_API
xqc_moqt_session_t *xqc_moqt_relay_peer_session(xqc_moqt_relay_peer_t *peer);

XQC_EXPORT_PUBLIC_API
void xqc_moqt_relay_peer_destroy(xqc_moqt_relay_peer_t *peer);

/*
 * Single-threaded, outside callbacks, after engine processing and on expiry.
 * now uses the engine's monotonic microsecond clock. Returns the next absolute
 * deadline, or zero with no pending deadline; also collects closed mappings.
 */
XQC_EXPORT_PUBLIC_API
xqc_usec_t xqc_moqt_relay_process(xqc_moqt_relay_t *relay, xqc_usec_t now);

XQC_EXPORT_PUBLIC_API
const xqc_moqt_relay_stats_t *xqc_moqt_relay_stats(
    const xqc_moqt_relay_t *relay);

#ifdef __cplusplus
}
#endif

#endif /* _XQC_MOQT_RELAY_H_INCLUDED_ */
