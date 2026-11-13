/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef _XQC_MOQT_RELAY_INTERNAL_H_INCLUDED_
#define _XQC_MOQT_RELAY_INTERNAL_H_INCLUDED_

#include <moq/xqc_moqt_relay.h>
#include "moq/moqt/xqc_moqt_codec.h"
#include "src/common/utils/var_buf/xqc_var_buf.h"
#include <openssl/sha.h>

#define XQC_MOQT_RELAY_DEFAULT_PEERS 64
#define XQC_MOQT_RELAY_DEFAULT_REQUESTS 1024
#define XQC_MOQT_RELAY_DEFAULT_STREAMS 1024
#define XQC_MOQT_RELAY_DEFAULT_BYTES (16 * 1024 * 1024)
#define XQC_MOQT_RELAY_DEFAULT_TIMEOUT (30 * 1000 * 1000)
#define XQC_MOQT_RELAY_HISTORY 32
#define XQC_MOQT_RELAY_RETRY_US 1000
#define XQC_MOQT_RELAY_UPDATE_CREDIT 1

typedef struct xqc_moqt_relay_request_s xqc_moqt_relay_request_t;
typedef struct xqc_moqt_relay_track_s xqc_moqt_relay_track_t;
typedef struct xqc_moqt_relay_stream_s xqc_moqt_relay_stream_t;
typedef struct xqc_moqt_relay_fetch_s xqc_moqt_relay_fetch_t;

typedef struct {
    xqc_moqt_object_t  object;
    uint8_t            digest[SHA256_DIGEST_LENGTH];
    unsigned           valid:1;
} xqc_moqt_relay_object_t;

struct xqc_moqt_relay_track_s {
    xqc_moqt_relay_track_t  *next;
    xqc_var_buf_t           *name;
    xqc_var_buf_t           *scope;
    size_t                   references;
    size_t                   recent_index;
    xqc_moqt_relay_object_t  recent[XQC_MOQT_RELAY_HISTORY];
};

struct xqc_moqt_relay_peer_s {
    xqc_moqt_relay_peer_t  *next;
    xqc_moqt_relay_t       *relay;
    xqc_moqt_session_t     *session;
    xqc_var_buf_t          *scope;
    void                   *user_data;
    unsigned                closed:1;
};

struct xqc_moqt_relay_request_s {
    xqc_moqt_relay_request_t  *next;
    xqc_moqt_relay_request_t  *parent;
    xqc_moqt_relay_peer_t     *peer;
    xqc_moqt_relay_track_t    *track;
    xqc_moqt_relay_request_t  *selected;
    xqc_moqt_relay_fetch_t    *fetch;
    xqc_moqt_request_t        *request;
    xqc_moqt_subscription_t   *subscription;
    xqc_var_buf_t             *state;
    xqc_var_buf_t             *response;
    xqc_var_buf_t             *candidate;
    xqc_var_buf_t             *update;
    uint64_t                   type;
    uint64_t                   publication_id;
    uint64_t                   done_code;
    xqc_usec_t                 deadline;
    xqc_usec_t                 operation_started;
    size_t                     pending;
    size_t                     recent_index;
    xqc_moqt_location_t        recent[XQC_MOQT_RELAY_HISTORY];
    size_t                     recent_count;
    unsigned                   upstream:1;
    unsigned                   established:1;
    unsigned                   waiting_update:1;
    unsigned                   registered:1;
    unsigned                   ending:1;
    unsigned                   stopped:1;
    unsigned                   forward:1;
};

struct xqc_moqt_relay_fetch_s {
    xqc_moqt_relay_fetch_t    *next;
    xqc_moqt_relay_request_t  *downstream;
    xqc_moqt_relay_request_t  *upstream;
    xqc_moqt_fetch_t          *input;
    xqc_moqt_fetch_t          *output;
    xqc_moqt_stream_t         *stream;
    xqc_usec_t                 deadline;
    unsigned                   closed:1;
};

struct xqc_moqt_relay_stream_s {
    xqc_moqt_relay_stream_t   *next;
    xqc_moqt_relay_request_t  *upstream;
    xqc_moqt_relay_request_t  *downstream;
    xqc_moqt_relay_fetch_t    *fetch;
    xqc_moqt_stream_t         *input;
    xqc_moqt_stream_t         *output;
    SHA256_CTX                 hash;
    xqc_usec_t                 received;
    unsigned                   skipping:1;
    unsigned                   finishing:1;
    unsigned                   closed:1;
};

struct xqc_moqt_relay_s {
    xqc_moqt_relay_config_t     config;
    xqc_moqt_relay_callbacks_t  callbacks;
    xqc_moqt_relay_stats_t      stats;
    uint64_t                    next_publication;
    xqc_moqt_relay_peer_t      *peers;
    xqc_moqt_relay_request_t   *requests;
    xqc_moqt_relay_track_t     *tracks;
    xqc_moqt_relay_fetch_t     *fetches;
    xqc_moqt_relay_stream_t    *streams;
};

void *xqc_moqt_relay_alloc(xqc_moqt_relay_t *relay, size_t size);
void xqc_moqt_relay_free(xqc_moqt_relay_t *relay, void *data, size_t size);
xqc_var_buf_t *xqc_moqt_relay_buffer(xqc_moqt_relay_t *relay,
    const void *data, size_t size);
void xqc_moqt_relay_buffer_free(xqc_moqt_relay_t *relay, xqc_var_buf_t *buf);
void xqc_moqt_relay_stop(xqc_moqt_relay_request_t *request, uint64_t error);
void xqc_moqt_relay_routes(xqc_moqt_relay_t *relay);
void xqc_moqt_relay_fetch_ready(xqc_moqt_fetch_t *fetch,
    xqc_moqt_subscription_t *subscription, void *user_data);
void xqc_moqt_relay_fetch_closed(xqc_moqt_fetch_t *fetch,
    const xqc_moqt_error_t *error, void *user_data);
void xqc_moqt_relay_object(xqc_moqt_subscription_t *subscription,
    xqc_moqt_stream_t *stream, const xqc_moqt_object_t *object,
    void *user_data);
void xqc_moqt_relay_stream_closed(xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *last, const xqc_moqt_error_t *error,
    void *user_data);
void xqc_moqt_relay_writable(xqc_moqt_session_t *session,
    xqc_moqt_stream_t *stream, void *user_data);
xqc_moqt_relay_request_t *xqc_moqt_relay_request_open(
    xqc_moqt_relay_request_t *downstream, xqc_moqt_relay_peer_t *peer,
    xqc_moqt_message_t *message);
void xqc_moqt_relay_fetch_response(xqc_moqt_relay_request_t *upstream,
    const xqc_moqt_message_t *message);
void xqc_moqt_relay_fetch_stop(xqc_moqt_relay_fetch_t *fetch,
    uint64_t error);
xqc_moqt_relay_request_t *xqc_moqt_relay_subscription_find(
    xqc_moqt_relay_peer_t *peer, xqc_moqt_subscription_t *subscription);
xqc_var_buf_t *xqc_moqt_relay_message_copy(xqc_moqt_relay_t *relay,
    const xqc_moqt_message_t *message, uint64_t context);
xqc_int_t xqc_moqt_relay_message_read(const xqc_var_buf_t *buf,
    uint64_t context, xqc_moqt_message_t *message);
xqc_usec_t xqc_moqt_relay_deadline(xqc_usec_t now, uint64_t milliseconds,
    xqc_usec_t maximum);

#endif /* _XQC_MOQT_RELAY_INTERNAL_H_INCLUDED_ */
