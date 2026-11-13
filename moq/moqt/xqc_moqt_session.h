/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef _XQC_MOQT_SESSION_H_INCLUDED_
#define _XQC_MOQT_SESSION_H_INCLUDED_

#include "include/moq/xqc_moqt.h"
#include "xqc_moqt_codec.h"
#include "src/common/utils/var_buf/xqc_var_buf.h"
#include "src/transport/xqc_conn.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

#define XQC_MOQT_DEFAULT_STREAMS 128
#define XQC_MOQT_CONTROL_STREAM_COUNT 2
#define XQC_MOQT_DEFAULT_BUFFERED_BYTES (1024 * 1024)
#define XQC_MOQT_DEFAULT_TIMEOUT (30 * XQC_MICROS_PER_SECOND)
#define XQC_MOQT_DEFAULT_REQUEST_UPDATES 16
#define XQC_MOQT_REQUEST_ID_RANGES 128
#define XQC_MOQT_CLIENT_FIRST_REQUEST_ID 0
#define XQC_MOQT_SERVER_FIRST_REQUEST_ID 1
#define XQC_MOQT_REQUEST_ID_STEP 2
#define XQC_MOQT_REQUEST_ID_PARITY_MASK 1u
#define XQC_MOQT_TX_OVERHEAD (sizeof(xqc_var_buf_t) + sizeof(xqc_list_buf_t))
#define XQC_MOQT_FETCH_STREAM 0x05
#define XQC_MOQT_PADDING_STREAM 0x132b3e28
#define XQC_MOQT_READ_CHUNK 4096
/* Retain a maximum Object header plus one transport read, never its payload. */
#define XQC_MOQT_RX_LIMIT (XQC_MOQT_KV_MAX_VALUE + 4 * XQC_VI64_MAX_LEN \
                          + XQC_MOQT_READ_CHUNK)

typedef enum {
    XQC_MOQT_STREAM_UNCLASSIFIED,
    XQC_MOQT_STREAM_CONTROL,
    XQC_MOQT_STREAM_REQUEST,
    XQC_MOQT_STREAM_SUBGROUP,
    XQC_MOQT_STREAM_FETCH,
    XQC_MOQT_STREAM_PADDING,
} xqc_moqt_stream_kind_t;

#define XQC_MOQT_DEFAULT_PRIORITY 128
#define XQC_MOQT_PROPERTY_OBJECT_TIMEOUT 0x02
#define XQC_MOQT_PROPERTY_SUBGROUP_TIMEOUT 0x06
#define XQC_MOQT_PROPERTY_PUBLISHER_PRIORITY 0x0e
#define XQC_MOQT_PROPERTY_GROUP_ORDER 0x22
#define XQC_MOQT_LOCATION_FILTER_MAX_FIELDS 5

typedef struct xqc_moqt_group_s xqc_moqt_group_t;
typedef struct xqc_moqt_subgroup_s xqc_moqt_subgroup_t;

/* Only active Subgroups are retained; payload belongs to Stream RX/TX. */
struct xqc_moqt_subgroup_s {
    xqc_moqt_subgroup_t    *next;
    xqc_moqt_group_t       *group;
    uint64_t                subgroup_id;
    uint64_t                minimum;
    uint64_t                maximum;
    uint64_t                first;
    uint64_t                last;
    size_t                  references;
    uint8_t                 priority;
    unsigned                has_object:1;
    unsigned                has_first:1;
    unsigned                has_last:1;
};

/* Track also retains one inline recent Group for Datagram-only delivery. */
struct xqc_moqt_group_s {
    xqc_moqt_group_t       *next;
    xqc_moqt_subgroup_t    *subgroups;
    uint64_t                group_id;
    uint64_t                largest_object;
    uint64_t                end_object;
    uint64_t                prior_group_gap;
    uint64_t                gap_start;
    uint64_t                gap_end;
    unsigned                valid:1;
    unsigned                has_largest:1;
    unsigned                has_end:1;
    unsigned                end_inclusive:1;
    unsigned                has_prior_group_gap:1;
    unsigned                has_gap:1;
};

typedef struct xqc_moqt_track_s {
    struct xqc_moqt_track_s    *next;
    xqc_var_buf_t              *name;
    xqc_moqt_location_t         largest;
    xqc_moqt_location_t         end;
    xqc_moqt_group_t            group;
    xqc_moqt_group_t           *groups;
    size_t                      references;
    uint64_t                    object_timeout;
    uint64_t                    subgroup_timeout;
    uint8_t                     publisher_priority;
    uint8_t                     group_order;
    unsigned                    local_publisher:1;
    unsigned                    has_largest:1;
    unsigned                    has_end:1;
    unsigned                    end_inclusive:1;
} xqc_moqt_track_t;

struct xqc_moqt_subscription_s {
    xqc_moqt_subscription_t    *next;
    xqc_moqt_track_t           *track;
    xqc_moqt_request_t         *request;
    xqc_moqt_session_t         *session;
    xqc_moqt_error_t            error;
    xqc_usec_t                  close_deadline;
    uint64_t                    stream_count;
    uint64_t                    finished_streams;
    uint64_t                    expected_streams;
    uint64_t                    object_timeout;
    uint64_t                    subgroup_timeout;
    unsigned                    active;
    xqc_moqt_location_t         start;
    xqc_moqt_location_t         end;
    uint64_t                    track_alias;
    uint8_t                     subscriber_priority;
    uint8_t                     publisher_priority;
    uint8_t                     group_order;
    unsigned                    forward:1;
    unsigned                    group_order_set:1;
    unsigned                    start_exclusive:1;
    unsigned                    established:1;
    unsigned                    stopped:1;
    unsigned                    done:1;
    unsigned                    shared_alias:1;
    unsigned                    closed:1;
};

struct xqc_moqt_fetch_s {
    xqc_moqt_fetch_t           *next;
    xqc_moqt_session_t         *session;
    xqc_moqt_request_t         *request;
    xqc_moqt_subscription_t    *subscription;
    xqc_moqt_stream_t          *stream;
    xqc_moqt_track_t           *track;
    xqc_moqt_fetch_info_t       info;
    xqc_usec_t                  deadline;
    unsigned                    active;
    unsigned                    confirmed:1;
    unsigned                    ready:1;
    unsigned                    opened:1;
    unsigned                    closed:1;
};

struct xqc_moqt_request_s {
    struct xqc_moqt_stream_s   *stream;
    uint64_t                    initial_type;
    uint64_t                    initial_request_id;
    uint64_t                    pending_sent_updates;
    uint64_t                    pending_received_updates;
    xqc_var_buf_t              *state;
    xqc_moqt_subscription_t    *subscription;
    xqc_moqt_fetch_t           *fetch;
    xqc_list_head_t             sent_updates;
    xqc_list_head_t             received_updates;
    xqc_list_head_t             namespaces;
    xqc_list_head_t             publications;
    xqc_usec_t                  response_deadline;
    xqc_usec_t                  goaway_deadline;
    xqc_moqt_error_t            error;
    unsigned                    local:1;
    unsigned                    responded:1;
    unsigned                    established:1;
    unsigned                    failed:1;
    unsigned                    has_error:1;
    unsigned                    done_sent:1;
    unsigned                    done_received:1;
    unsigned                    goaway_sent:1;
    unsigned                    goaway_received:1;
};

typedef struct {
    xqc_moqt_track_t           *track;
    xqc_moqt_subscription_t    *subscription; /* Sending side only. */
    xqc_moqt_subgroup_t        *subgroup;
    xqc_moqt_fetch_t           *fetch;
    xqc_moqt_fetch_history_t    history;
    xqc_moqt_object_t           object;
    uint64_t                    track_alias;
    uint64_t                    flags;
    uint64_t                    error;
    size_t                      header_length;
    size_t                      properties_offset;
    size_t                      prefix_length;
    xqc_usec_t                  object_time;
    xqc_usec_t                  finish_time;
    uint64_t                    object_timeout;
    uint64_t                    subgroup_timeout;
    unsigned                    has_object_timeout:1;
    unsigned                    has_subgroup_timeout:1;
    unsigned                    object_header:1;
    unsigned                    has_object:1;
    unsigned                    blocked:1;
    unsigned                    notified:1;
    unsigned                    has_error:1;
    unsigned                    reset_pending:1;
} xqc_moqt_data_stream_t;

struct xqc_moqt_stream_s {
    xqc_moqt_session_t         *session;
    struct xqc_moqt_stream_s   *next;
    xqc_stream_t               *transport_stream;
#ifdef XQC_ENABLE_WEBTRANSPORT
    struct xqc_wt_stream_base_s *wt_stream;
#endif
    xqc_moqt_stream_kind_t      kind;
    xqc_var_buf_t               rx;
    xqc_list_head_t             tx;
    xqc_usec_t                  deadline;
    uint64_t                    tx_order;
    union {
        xqc_moqt_request_t      request;
        xqc_moqt_data_stream_t  data;
    } state;
    unsigned                    active;
    unsigned                    tx_blocked:1;
    unsigned                    tx_fin:1;
    unsigned                    tx_fin_sent:1;
    unsigned                    rx_fin:1;
    unsigned                    discarded:1;
    unsigned                    reading:1;
    unsigned                    writing:1;
};

struct xqc_moqt_session_s {
    xqc_connection_t           *conn;
#ifdef XQC_ENABLE_WEBTRANSPORT
    struct xqc_webtransport_session_s *wt_session;
    uint32_t                    wt_close_error;
    unsigned                    wt_close_pending:1;
#endif
    xqc_moqt_config_t           config;
    xqc_moqt_callbacks_t        callbacks;
    void                       *user_data;
    xqc_moqt_receive_limits_t   local_limits;
    xqc_moqt_receive_limits_t   peer_limits;
    xqc_moqt_stream_t          *streams;
    xqc_moqt_track_t           *tracks;
    xqc_moqt_subscription_t    *subscriptions;
    xqc_moqt_fetch_t           *fetches;
    xqc_moqt_stream_t          *control_tx;
    xqc_moqt_stream_t          *control_rx;
    xqc_var_buf_t              *setup;
    size_t                      stream_count;
    size_t                      buffered_bytes;
    xqc_gp_timer_id_t           timer;
    xqc_usec_t                  setup_deadline;
    xqc_usec_t                  goaway_deadline;
    uint64_t                    next_request_id;
    uint64_t                    tx_order;
    uint64_t                    next_track_alias;
    xqc_pktno_range_t           request_ids[XQC_MOQT_REQUEST_ID_RANGES];
    size_t                      request_id_ranges;
    unsigned                    request_ids_exhausted:1;
    unsigned                    track_aliases_exhausted:1;
    unsigned                    datagram_blocked:1;
    unsigned                    flushing:1;
    unsigned                    started:1;
    unsigned                    setup_sent:1;
    unsigned                    setup_received:1;
    unsigned                    ready:1;
    unsigned                    closed:1;
    unsigned                    goaway_sent:1;
    unsigned                    goaway_received:1;
    unsigned                    webtransport:1;
};

xqc_moqt_session_t *xqc_moqt_session_create_transport(xqc_connection_t *conn,
    const xqc_moqt_config_t *config, const xqc_moqt_callbacks_t *callbacks,
    void *data, xqc_bool_t webtransport);
void xqc_moqt_notify_closed(xqc_moqt_session_t *s, uint64_t error);
xqc_moqt_stream_t *xqc_moqt_stream_allocate(xqc_moqt_session_t *s,
    xqc_stream_t *transport);
xqc_moqt_stream_t *xqc_moqt_transport_open(xqc_moqt_session_t *s,
    xqc_stream_direction_t direction);
ssize_t xqc_moqt_transport_send(xqc_moqt_stream_t *st, const void *data,
    size_t len, uint8_t fin);
uint64_t xqc_moqt_transport_offset(xqc_moqt_stream_t *st);
void xqc_moqt_transport_reset(xqc_moqt_stream_t *st, uint64_t error);
size_t xqc_moqt_transport_mss(xqc_moqt_session_t *s);
xqc_int_t xqc_moqt_transport_datagram(xqc_moqt_session_t *s,
    const void *data, size_t len);
#ifdef XQC_ENABLE_WEBTRANSPORT
void xqc_moqt_webtransport_close(xqc_moqt_session_t *s, uint64_t error);
void xqc_moqt_webtransport_detach(xqc_moqt_session_t *s);
#endif

xqc_moqt_track_t *xqc_moqt_track_get(xqc_moqt_session_t *s,
    const xqc_moqt_message_t *message, xqc_int_t publisher);
xqc_int_t xqc_moqt_location_filter_apply(xqc_moqt_location_t *start,
    xqc_moqt_location_t *end, xqc_int_t *exclusive,
    const xqc_moq_message_parameter_t *parameter,
    const xqc_moqt_location_t *largest, xqc_int_t has_largest);
xqc_int_t xqc_moqt_track_properties_read(const struct iovec *bytes,
    xqc_moqt_track_t *defaults, size_t *count);
uint64_t xqc_moqt_fetch_create(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *message);
uint64_t xqc_moqt_fetch_apply(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *message);
uint64_t xqc_moqt_fill_apply(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *state, const xqc_moqt_message_t *trigger,
    const xqc_moqt_message_t *reply);
void xqc_moqt_fetch_ready(xqc_moqt_request_t *request, uint64_t id);
void xqc_moqt_fill_cancel(xqc_moqt_subscription_t *subscription);
void xqc_moqt_fetch_release(xqc_moqt_request_t *request);
void xqc_moqt_fetch_complete(xqc_moqt_fetch_t *fetch,
    const xqc_moqt_error_t *error);
void xqc_moqt_fetch_stream_closed(xqc_moqt_stream_t *stream);
xqc_int_t xqc_moqt_fetch_attach(xqc_moqt_stream_t *stream);
xqc_int_t xqc_moqt_fetch_contains(const xqc_moqt_fetch_t *fetch,
    const xqc_moqt_object_t *object);

extern const xqc_stream_callbacks_t xqc_moqt_stream_callbacks;
extern const xqc_datagram_callbacks_t xqc_moqt_datagram_callbacks;

/* Draft-22 sections 6.3 and 9: shared by QUIC callbacks and parser tests. */
xqc_int_t xqc_moqt_stream_input(xqc_moqt_stream_t *stream, const uint8_t *data,
    size_t len, uint8_t fin);
void xqc_moqt_timer_update(xqc_moqt_session_t *session);
void xqc_moqt_session_timeout(xqc_gp_timer_id_t id, xqc_usec_t now, void *data);
xqc_int_t xqc_moqt_stream_flush(xqc_moqt_stream_t *stream);
xqc_var_buf_t *xqc_moqt_buffer_create(xqc_moqt_session_t *s, size_t len,
    size_t overhead);
void xqc_moqt_buffer_free(xqc_moqt_session_t *s, xqc_var_buf_t *buf,
    size_t overhead);
xqc_int_t xqc_moqt_queue(xqc_moqt_session_t *s, xqc_list_head_t *head,
    xqc_var_buf_t *buf);
void xqc_moqt_dequeue(xqc_moqt_session_t *s, xqc_list_buf_t *entry);
xqc_int_t xqc_moqt_token_check(const xqc_moqt_token_t *tokens, size_t count,
    const xqc_moqt_token_t *token);
uint64_t xqc_moqt_token_decode(const struct iovec *bytes, xqc_int_t from_client,
    xqc_int_t setup, xqc_moqt_token_t *token);
uint64_t xqc_moqt_request_input(xqc_moqt_stream_t *st,
    const uint8_t *data, size_t len);
void xqc_moqt_request_closed(xqc_moqt_request_t *r);
void xqc_moqt_request_fin(xqc_moqt_request_t *r);

xqc_int_t xqc_moqt_is_local_publisher(const xqc_moqt_request_t *request);
uint64_t xqc_moqt_subscription_create(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *message);
uint64_t xqc_moqt_subscription_apply(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *message);
void xqc_moqt_subscription_release(xqc_moqt_request_t *request);
void xqc_moqt_subscription_done(xqc_moqt_subscription_t *sub,
    const xqc_moqt_message_t *message);
void xqc_moqt_subscription_close(xqc_moqt_subscription_t *sub);
void xqc_moqt_subscription_free(xqc_moqt_subscription_t *sub);
void xqc_moqt_subscription_check_done(xqc_moqt_subscription_t *sub);
xqc_moqt_subscription_t *xqc_moqt_subscriptions_hold(xqc_moqt_session_t *s);
void xqc_moqt_subscriptions_release(xqc_moqt_subscription_t *head);

xqc_int_t xqc_moqt_location_compare(const xqc_moqt_location_t *a,
    const xqc_moqt_location_t *b);
void xqc_moqt_datagram_input(xqc_moqt_session_t *session,
    const uint8_t *data, size_t len);
void xqc_moqt_datagram_writable(xqc_moqt_session_t *session);

void xqc_moqt_track_release(xqc_moqt_session_t *s, xqc_moqt_track_t *track);
void xqc_moqt_subscription_data_update(xqc_moqt_subscription_t *sub);
xqc_int_t xqc_moqt_subgroup_input(xqc_moqt_stream_t *stream, uint8_t fin);
void xqc_moqt_subgroup_closed(xqc_moqt_stream_t *stream);
void xqc_moqt_subgroup_notify(xqc_moqt_stream_t *stream);
xqc_usec_t xqc_moqt_subgroup_deadline(xqc_moqt_stream_t *stream);
xqc_int_t xqc_moqt_object_is_expired(xqc_moqt_stream_t *stream,
    xqc_usec_t submitted, xqc_usec_t now);

xqc_moqt_stream_t *xqc_moqt_streams_hold(xqc_moqt_session_t *s);
void xqc_moqt_streams_release(xqc_moqt_stream_t *head);
xqc_int_t xqc_moqt_data_compare(const xqc_moqt_subscription_t *a,
    const xqc_moqt_object_t *oa, const xqc_moqt_fetch_t *fa,
    const xqc_moqt_subscription_t *b, const xqc_moqt_object_t *ob,
    const xqc_moqt_fetch_t *fb);

#endif
