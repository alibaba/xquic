/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "xqc_moqt_relay_test.h"
#include "moq/moqt_relay/xqc_moqt_relay.h"
#include "moq/moqt/xqc_moqt_session.h"
#include "src/transport/xqc_stream.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

#define XQC_TEST_RELAY_CAPACITY (1024 * 1024)
#define XQC_TEST_RELAY_PEERS 4
#define XQC_TEST_RELAY_STREAM_ID_STEP 4
#define XQC_TEST_RELAY_PUBLISHER 0
#define XQC_TEST_RELAY_OTHER_PUBLISHER 1
#define XQC_TEST_RELAY_SUBSCRIBER 2
#define XQC_TEST_RELAY_OTHER_SUBSCRIBER 3

typedef struct {
    xqc_engine_t           *engine;
    xqc_connection_t       *conn;
    xqc_moqt_relay_peer_t  *peer;
    xqc_moqt_session_t     *session;
    uint64_t                next_stream;
    uint64_t                next_request;
    uint64_t                denied;
    xqc_bool_t              forward_denied;
} xqc_test_relay_peer_t;

typedef struct {
    xqc_moqt_relay_t      *relay;
    xqc_test_relay_peer_t  peers[XQC_TEST_RELAY_PEERS];
} xqc_test_relay_t;

static uint64_t
xqc_test_relay_setup(xqc_moqt_relay_peer_t *peer,
    const xqc_moqt_setup_t *setup, void *data)
{
    return XQC_MOQT_NO_ERROR;
}

static xqc_int_t
xqc_test_relay_authorize(xqc_moqt_relay_peer_t *peer,
    const xqc_moqt_message_t *message, const xqc_moqt_message_t *candidate,
    uint64_t *error, void *data)
{
    xqc_test_relay_peer_t *p = data;
    *error = XQC_MOQT_REQUEST_UNAUTHORIZED;
    return p->denied == message->type ? XQC_ERROR : XQC_OK;
}

static xqc_int_t
xqc_test_relay_forward(xqc_moqt_relay_peer_t *peer,
    xqc_moqt_message_t *message, void *data)
{
    xqc_test_relay_peer_t *p = data;
    for (size_t i = 0; i < message->parameter_count; i++) {
        CU_ASSERT_NOT_EQUAL(message->parameters[i].type,
                            XQC_MOQT_PARAM_AUTHORIZATION_TOKEN);
    }
    return p->forward_denied ? XQC_ERROR : XQC_OK;
}

static const xqc_moqt_relay_callbacks_t xqc_test_relay_callbacks = {
    .on_setup = xqc_test_relay_setup,
    .on_authorize = xqc_test_relay_authorize,
    .on_forward = xqc_test_relay_forward,
};

static void
xqc_test_relay_init(xqc_test_relay_t *f)
{
    xqc_memzero(f, sizeof(*f));
    xqc_moqt_relay_config_t config;
    xqc_moqt_relay_config_init(&config);
    f->relay = xqc_moqt_relay_create(&config, &xqc_test_relay_callbacks);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f->relay);
    for (size_t i = 0; i < XQC_TEST_RELAY_PEERS; i++) {
        xqc_test_relay_peer_t *p = &f->peers[i];
        xqc_moqt_config_t session_config;
        xqc_moqt_config_init(&session_config, XQC_MOQT_VERSION_DRAFT_22);
        p->engine = test_create_engine();
        CU_ASSERT_PTR_NOT_NULL_FATAL(p->engine);
        xqc_conn_callbacks_t callbacks;
        xqc_memzero(&callbacks, sizeof(callbacks));
        CU_ASSERT_EQUAL(xqc_moqt_init_alpn(p->engine, &session_config,
                                           &callbacks), XQC_OK);
        xqc_conn_ssl_config_t ssl;
        xqc_memzero(&ssl, sizeof(ssl));
        xqc_conn_settings_t settings = {.proto_version = XQC_VERSION_V1,
            .max_datagram_frame_size = XQC_MAX_PACKET_OUT_SIZE,
            .max_pkt_out_size = XQC_MAX_PACKET_OUT_SIZE};
        const xqc_cid_t *cid = xqc_moqt_connect(p->engine, &session_config,
            &settings, NULL, 0, "localhost", &ssl, NULL, 0, p);
        CU_ASSERT_PTR_NOT_NULL_FATAL(cid);
        p->conn = xqc_engine_conns_hash_find(p->engine, cid, 's');
        p->engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
        p->conn->conn_type = XQC_CONN_TYPE_SERVER;
        p->conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED
                              | XQC_CONN_FLAG_CAN_SEND_1RTT;
        p->conn->remote_settings.max_datagram_frame_size
            = XQC_MAX_PACKET_OUT_SIZE;
        p->conn->remote_settings.max_stream_data_uni = XQC_TEST_RELAY_CAPACITY;
        p->conn->remote_settings.max_stream_data_bidi_local
            = XQC_TEST_RELAY_CAPACITY;
        p->conn->remote_settings.max_stream_data_bidi_remote
            = XQC_TEST_RELAY_CAPACITY;
        p->conn->conn_flow_ctl.fc_max_data_can_send = XQC_TEST_RELAY_CAPACITY;
        p->conn->conn_flow_ctl.fc_max_streams_uni_can_send
            = XQC_MOQT_DEFAULT_STREAMS;
        p->conn->conn_flow_ctl.fc_max_streams_bidi_can_send
            = XQC_MOQT_DEFAULT_STREAMS;
        struct iovec scope = {(void *)"example/moq", sizeof("example/moq") - 1};
        p->peer = xqc_moqt_relay_peer_create(f->relay, p->conn,
                                             &session_config, &scope, p);
        CU_ASSERT_PTR_NOT_NULL_FATAL(p->peer);
        p->session = xqc_moqt_relay_peer_session(p->peer);
        CU_ASSERT_EQUAL(xqc_moqt_session_start(p->session), XQC_OK);
        xqc_stream_t *native = xqc_create_stream_with_conn(p->conn,
            XQC_CLI_UNI, XQC_CLI_UNI, NULL, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(native);
        const uint8_t setup[] = {0xaf, 0, 0, 0};
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(native->user_data, setup,
                                              sizeof(setup), 0), XQC_OK);
        CU_ASSERT_TRUE(p->session->ready);
    }
}

static void
xqc_test_relay_destroy(xqc_test_relay_t *f)
{
    for (size_t i = 0; i < XQC_TEST_RELAY_PEERS; i++) {
        xqc_moqt_relay_peer_destroy(f->peers[i].peer);
    }
    xqc_moqt_relay_process(f->relay, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(f->relay->stats.requests, 0);
    CU_ASSERT_EQUAL(f->relay->stats.streams, 0);
    CU_ASSERT_EQUAL(f->relay->stats.peers, 0);
    CU_ASSERT_EQUAL(f->relay->stats.bytes, sizeof(*f->relay));
    xqc_moqt_relay_destroy(f->relay);
    for (size_t i = 0; i < XQC_TEST_RELAY_PEERS; i++) {
        f->peers[i].engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
        xqc_engine_destroy(f->peers[i].engine);
    }
}

static xqc_moqt_message_t
xqc_test_relay_message(uint64_t type)
{
    xqc_moqt_message_t m;
    xqc_memzero(&m, sizeof(m));
    m.type = type;
    m.track_namespace.count = 1;
    m.track_namespace.fields[0] = (struct iovec){(void *)"media", 5};
    m.track_name = (struct iovec){(void *)"video", 5};
    return m;
}

static void
xqc_test_relay_input(xqc_moqt_stream_t *st, xqc_moqt_message_t *m,
    uint64_t context)
{
    uint8_t wire[XQC_MOQT_MESSAGE_MAX_BODY];
    xqc_int_t n = xqc_moqt_message_encode(m, context, wire, sizeof(wire));
    CU_ASSERT(n > 0);
    if (n > 0) {
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(st, wire, n, 0), XQC_OK);
    }
}

static xqc_moqt_request_t *
xqc_test_relay_receive(xqc_test_relay_peer_t *p, xqc_moqt_message_t *m)
{
    xqc_stream_t *native = xqc_create_stream_with_conn(p->conn,
        p->next_stream, XQC_CLI_BID, NULL, NULL);
    p->next_stream += XQC_TEST_RELAY_STREAM_ID_STEP;
    CU_ASSERT_PTR_NOT_NULL(native);
    if (native == NULL) {
        return NULL;
    }
    m->request_id = p->next_request;
    p->next_request += XQC_MOQT_REQUEST_ID_STEP;
    xqc_moqt_stream_t *st = native->user_data;
    xqc_test_relay_input(st, m, 0);
    return &st->state.request;
}

static xqc_moqt_relay_request_t *
xqc_test_relay_record(xqc_moqt_relay_t *r, xqc_moqt_request_t *request)
{
    for (xqc_moqt_relay_request_t *q = r->requests; q; q = q->next) {
        if (q->request == request) {
            return q;
        }
    }
    return NULL;
}

static void
xqc_test_relay_establish(xqc_moqt_relay_t *r)
{
    for (xqc_moqt_relay_request_t *q = r->requests; q; q = q->next) {
        if (q->upstream && !q->established && !q->stopped) {
            xqc_moqt_message_t m;
            xqc_memzero(&m, sizeof(m));
            m.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
            m.track_alias = xqc_moqt_request_id(q->request);
            xqc_test_relay_input(q->request->stream, &m, q->type);
        }
    }
}

void
xqc_test_moqt_relay_config(void)
{
    xqc_moqt_relay_config_t config;
    xqc_moqt_relay_config_init(&config);
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_create(NULL, &xqc_test_relay_callbacks));
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_create(&config, NULL));
    config.max_bytes = 1;
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_create(&config,
                                             &xqc_test_relay_callbacks));
    xqc_moqt_relay_config_init(&config);
    xqc_moqt_relay_t *r = xqc_moqt_relay_create(&config,
                                                &xqc_test_relay_callbacks);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r);
    CU_ASSERT_EQUAL(xqc_moqt_relay_stats(r)->bytes, sizeof(*r));
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_alloc(r, config.max_bytes));
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_buffer(r, NULL, config.max_bytes));
    CU_ASSERT_EQUAL(xqc_moqt_relay_process(r, 0), 0);
    CU_ASSERT_EQUAL(xqc_moqt_relay_process(NULL, 0), 0);
    xqc_moqt_relay_destroy(NULL);
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_peer_session(NULL));
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_stats(NULL));
    CU_ASSERT_FALSE(xqc_moqt_subscription_is_matching(NULL, NULL));
    xqc_moqt_config_t endpoint;
    xqc_moqt_config_init(&endpoint, XQC_MOQT_VERSION_DRAFT_22);
    struct iovec scope = {(void *)"test", 4};
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_peer_create(NULL, NULL, &endpoint,
                                                  &scope, NULL));
    endpoint.setup_option_count = XQC_MOQT_MAX_OPTIONS + 1;
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_peer_create(r, NULL, &endpoint,
                                                  &scope, NULL));
    endpoint.setup_option_count = 0;
    r->config.max_bytes = sizeof(*r);
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_peer_create(r, NULL, &endpoint,
                                                  &scope, NULL));
    r->config.max_bytes += sizeof(xqc_moqt_relay_peer_t);
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_peer_create(r, NULL, &endpoint,
                                                  &scope, NULL));
    r->config.max_bytes = config.max_bytes;
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_peer_create(r, NULL, &endpoint,
                                                  &scope, NULL));
    CU_ASSERT_EQUAL(r->stats.bytes, sizeof(*r));
    CU_ASSERT_EQUAL(xqc_moqt_relay_deadline(UINT64_MAX, UINT64_MAX, 1),
                    UINT64_MAX);
    xqc_moqt_relay_destroy(r);
}

void
xqc_test_moqt_relay_routes(void)
{
    /* Draft-22 sections 4/7.4/7.6: sources and Established are distinct. */
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(
        XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE);
    xqc_moqt_request_t *watch = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_TRUE(watch->established);
    m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    xqc_moqt_request_t *a = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    xqc_moqt_request_t *b = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_OTHER_PUBLISHER], &m);
    CU_ASSERT_FALSE(xqc_list_empty(&watch->namespaces));
    CU_ASSERT_PTR_EQUAL(watch->namespaces.next, watch->namespaces.prev);
    m.type = XQC_MOQT_MSG_SUBSCRIBE;
    uint8_t token[] = {3, 3, 0, 't'};
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_AUTHORIZATION_TOKEN, sizeof(token), token};
    xqc_moqt_request_t *down = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_moqt_request_t *other = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER], &m);
    CU_ASSERT_FALSE(down->responded);
    CU_ASSERT_FALSE(other->responded);
    size_t upstream = 0;
    for (xqc_moqt_relay_request_t *q = f.relay->requests; q; q = q->next) {
        upstream += q->upstream;
    }
    CU_ASSERT_EQUAL(upstream, 4);
    xqc_test_relay_establish(f.relay);
    CU_ASSERT_TRUE(down->established);
    CU_ASSERT_TRUE(other->established);
    /* Reject the new demand if its second publisher cannot be admitted. */
    size_t max_requests = f.relay->config.max_requests;
    f.relay->config.max_requests = f.relay->stats.requests + 2;
    xqc_moqt_request_t *limited = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_EQUAL(limited->error.code, XQC_MOQT_REQUEST_EXCESSIVE_LOAD);
    CU_ASSERT_FALSE(other->subscription->stopped);
    f.relay->config.max_requests = max_requests;
    xqc_moqt_request_cancel(a, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_FALSE(xqc_list_empty(&watch->namespaces));
    xqc_moqt_request_cancel(b, XQC_MOQT_RESET_CANCELLED);
    /* Physical close is what ends the registration in this unit fixture. */
    xqc_moqt_stream_callbacks.stream_close_notify(a->stream->transport_stream,
                                                  a->stream);
    xqc_moqt_stream_callbacks.stream_close_notify(b->stream->transport_stream,
                                                  b->stream);
    CU_ASSERT_TRUE(xqc_list_empty(&watch->namespaces));
    CU_ASSERT_FALSE(down->subscription->stopped);
    xqc_moqt_subscription_cancel(down->subscription, XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_FALSE(other->subscription->stopped);
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_errors(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    xqc_moqt_request_t *missing = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_EQUAL(missing->error.code, XQC_MOQT_REQUEST_DOES_NOT_EXIST);
    uint8_t wait[] = {10};
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_RENDEZVOUS_TIMEOUT, sizeof(wait), wait};
    xqc_moqt_request_t *pending = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER], &m);
    CU_ASSERT_FALSE(pending->responded);
    xqc_moqt_relay_request_t *record = xqc_test_relay_record(f.relay, pending);
    CU_ASSERT_PTR_NOT_NULL_FATAL(record);
    CU_ASSERT(record->deadline > 0);
    xqc_moqt_relay_process(f.relay, record->deadline);
    CU_ASSERT_EQUAL(f.relay->stats.timeouts, 1);
    CU_ASSERT_TRUE(pending->failed);
    /* A later registration wakes only a still-pending rendezvous. */
    xqc_moqt_request_t *late = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_FALSE(late->responded);
    m = xqc_test_relay_message(XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_OTHER_PUBLISHER], &m);
    CU_ASSERT_FALSE(late->responded);
    xqc_test_relay_establish(f.relay);
    CU_ASSERT_TRUE(late->established);
    CU_ASSERT_TRUE(record->stopped);
    CU_ASSERT_FALSE(pending->established);
    f.peers[XQC_TEST_RELAY_PUBLISHER].denied = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    m = xqc_test_relay_message(XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_moqt_request_t *denied = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    CU_ASSERT_EQUAL(denied->error.code, XQC_MOQT_REQUEST_UNAUTHORIZED);
    m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    m.track_namespace.fields[0] = (struct iovec){(void *)".session", 8};
    xqc_moqt_request_t *local = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_EQUAL(local->error.code, XQC_MOQT_REQUEST_DOES_NOT_EXIST);
    /* A sole publisher's rejection cannot establish the downstream request. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    m.track_name = (struct iovec){(void *)"rejected", 8};
    xqc_moqt_request_t *rejected = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_moqt_relay_request_t *up = f.relay->requests;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_ERROR;
    m.error.code = XQC_MOQT_REQUEST_UNAUTHORIZED;
    xqc_test_relay_input(up->request->stream, &m, up->type);
    CU_ASSERT_EQUAL(rejected->error.code, XQC_MOQT_REQUEST_UNAUTHORIZED);
    CU_ASSERT_FALSE(rejected->established);
    CU_ASSERT_FALSE(late->subscription->stopped);
    /* A reset delivered through read_notify must remain stream-scoped. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_moqt_request_t *reset = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_OTHER_PUBLISHER], &m);
    xqc_moqt_stream_t *st = reset->stream;
    CU_ASSERT_EQUAL(xqc_moqt_stream_callbacks.stream_read_notify(
        st->transport_stream, st), XQC_OK);
    CU_ASSERT_FALSE(reset->failed);
    st->transport_stream->stream_state_recv = XQC_RECV_STREAM_ST_RESET_RECVD;
    st->transport_stream->stream_err = XQC_MOQT_RESET_CANCELLED;
    CU_ASSERT_EQUAL(xqc_moqt_stream_callbacks.stream_read_notify(
        st->transport_stream, st), XQC_OK);
    CU_ASSERT_TRUE(reset->failed);
    CU_ASSERT_FALSE(st->session->closed);
    CU_ASSERT_EQUAL(st->session->conn->conn_err, 0);
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_delivery(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(
        XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    m.type = XQC_MOQT_MSG_SUBSCRIBE;
    xqc_moqt_request_t *down = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_test_relay_establish(f.relay);
    xqc_moqt_relay_request_t *record = xqc_test_relay_record(f.relay, down);
    CU_ASSERT_PTR_NOT_NULL_FATAL(record->selected);
    xqc_moqt_relay_request_t *up = record->selected;
    uint8_t bytes[] = {0, 1, 2, 255};
    xqc_moqt_object_t object;
    xqc_memzero(&object, sizeof(object));
    object.group_id = 1;
    object.datagram = 1;
    object.priority = XQC_MOQT_DEFAULT_PRIORITY;
    object.payload = (struct iovec){bytes, sizeof(bytes)};
    object.payload_length = sizeof(bytes);
    uint8_t wire[256];
    xqc_int_t n = xqc_moqt_datagram_encode(up->subscription->track_alias,
                                           &object, wire, sizeof(wire));
    CU_ASSERT(n > 0);
    xqc_moqt_datagram_input(up->peer->session, wire, n);
    CU_ASSERT_EQUAL(f.relay->stats.forwarded, 1);
    xqc_moqt_datagram_input(up->peer->session, wire, n);
    CU_ASSERT_EQUAL(f.relay->stats.duplicates, 1);

    /* Subgroup fields and fragment timing are borrowed from the endpoint. */
    xqc_stream_t *native = xqc_create_stream_with_conn(
        f.peers[XQC_TEST_RELAY_PUBLISHER].conn,
        XQC_CLI_UNI + XQC_TEST_RELAY_STREAM_ID_STEP, XQC_CLI_UNI, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(native);
    xqc_moqt_stream_t *input = native->user_data;
    object.group_id = 2;
    object.datagram = 0;
    object.first_in_subgroup = 1;
    uint64_t flags = XQC_MOQT_SUBGROUP_FIXED_BITS
        | XQC_MOQT_SUBGROUP_PROPERTIES | XQC_MOQT_SUBGROUP_EXPLICIT_ID
        | XQC_MOQT_SUBGROUP_FIRST_OBJECT | XQC_MOQT_SUBGROUP_END_GROUP;
    n = xqc_moqt_subgroup_header_encode(up->subscription->track_alias,
                                        flags, &object, wire, sizeof(wire));
    CU_ASSERT(n > 0);
    xqc_int_t header = xqc_moqt_object_header_encode(flags, NULL, &object,
                                                     wire + n,
                                                     sizeof(wire) - n);
    CU_ASSERT(header > 0);
    n += header;
    xqc_memcpy(wire + n, bytes, sizeof(bytes));
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(input, wire, n + 1, 0), XQC_OK);
    CU_ASSERT_TRUE(xqc_moqt_stream_end_of_group(input));
    CU_ASSERT(xqc_moqt_stream_object_received_at(input) > 0);
    CU_ASSERT_FALSE(xqc_moqt_stream_end_of_group(NULL));
    CU_ASSERT_EQUAL(xqc_moqt_stream_object_received_at(NULL), 0);
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(input, bytes + 1,
                                          sizeof(bytes) - 1, 0), XQC_OK);
    xqc_moqt_relay_stream_t *flow = f.relay->streams;
    xqc_moqt_stream_t *output = flow->output;
    xqc_moqt_session_t *destination = output->session;
    size_t budget = destination->config.max_buffered_bytes;
    destination->config.max_buffered_bytes = destination->buffered_bytes;
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(input, NULL, 0, 1), XQC_OK);
    CU_ASSERT_TRUE(flow->finishing);
    CU_ASSERT_FALSE(output->tx_fin);
    output->session->config.max_buffered_bytes = budget;
    xqc_moqt_relay_writable(output->session, output, record->peer);
    CU_ASSERT_FALSE(flow->finishing);
    CU_ASSERT_TRUE(output->tx_fin);
    CU_ASSERT_EQUAL(f.relay->stats.forwarded, 2);
    xqc_moqt_object_t late = object;
    late.object_id++;
    CU_ASSERT_TRUE(xqc_moqt_subscription_object_is_obsolete(
        down->subscription, &late));
    late.group_id++;
    CU_ASSERT_FALSE(xqc_moqt_subscription_object_is_obsolete(
        down->subscription, &late));

    /* A duplicate reliable object is checked but not delivered twice. */
    native = xqc_create_stream_with_conn(
        f.peers[XQC_TEST_RELAY_PUBLISHER].conn,
        XQC_CLI_UNI + 2 * XQC_TEST_RELAY_STREAM_ID_STEP,
        XQC_CLI_UNI, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(native);
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(native->user_data, wire,
                                          n + sizeof(bytes), 1), XQC_OK);
    CU_ASSERT_EQUAL(f.relay->stats.duplicates, 2);
    CU_ASSERT_EQUAL(f.relay->stats.forwarded, 2);
    CU_ASSERT_FALSE(record->stopped);

    object.group_id = 1;
    object.datagram = 1;
    object.first_in_subgroup = 0;
    bytes[0]++;
    n = xqc_moqt_datagram_encode(up->subscription->track_alias,
                                 &object, wire, sizeof(wire));
    xqc_moqt_datagram_input(up->peer->session, wire, n);
    CU_ASSERT_EQUAL(f.relay->stats.malformed, 1);
    CU_ASSERT_TRUE(record->stopped);
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_history(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(
        XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    m = xqc_test_relay_message(XQC_MOQT_MSG_FETCH);
    xqc_moqt_request_t *down = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_FALSE(down->responded);
    xqc_moqt_relay_request_t *record = xqc_test_relay_record(f.relay, down);
    xqc_moqt_relay_request_t *up = f.relay->requests;
    CU_ASSERT_PTR_EQUAL(up->parent, record);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_FETCH_OK;
    m.end_group = 1;
    m.end_object = 2;
    xqc_test_relay_input(up->request->stream, &m, XQC_MOQT_MSG_FETCH);
    CU_ASSERT_TRUE(down->established);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f.relay->fetches);
    xqc_moqt_relay_fetch_t *fetch = f.relay->fetches;
    CU_ASSERT_PTR_NOT_NULL(fetch->input);
    CU_ASSERT_PTR_NOT_NULL(fetch->output);
    CU_ASSERT_PTR_NOT_NULL(fetch->stream);
    xqc_moqt_relay_process(f.relay, fetch->deadline);
    CU_ASSERT_PTR_NULL(f.relay->fetches);
    CU_ASSERT_EQUAL(f.relay->stats.timeouts, 1);
    /* An empty historical stream still forwards its FIN exactly once. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_FETCH);
    down = xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    up = f.relay->requests;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_FETCH_OK;
    m.end_group = 1;
    m.end_object = 2;
    xqc_test_relay_input(up->request->stream, &m, XQC_MOQT_MSG_FETCH);
    fetch = f.relay->fetches;
    xqc_moqt_stream_t *output = fetch->stream;
    xqc_stream_t *native = xqc_create_stream_with_conn(
        f.peers[XQC_TEST_RELAY_PUBLISHER].conn,
        XQC_CLI_UNI + XQC_TEST_RELAY_STREAM_ID_STEP, XQC_CLI_UNI, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(native);
    uint8_t wire[2 * XQC_VI64_MAX_LEN];
    xqc_int_t length = xqc_vi64_write(wire, wire + sizeof(wire),
                                      XQC_MOQT_FETCH_STREAM);
    length += xqc_vi64_write(wire + length, wire + sizeof(wire),
                             xqc_moqt_fetch_info(fetch->input)->request_id);
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(native->user_data, wire, length, 1),
                    XQC_OK);
    CU_ASSERT_TRUE(fetch->closed);
    CU_ASSERT_TRUE(output->tx_fin);
    CU_ASSERT_FALSE(output->state.data.has_error);
    /* TRACK_STATUS forwards a real snapshot and bounds a silent publisher. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_TRACK_STATUS);
    down = xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    up = f.relay->requests;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_OK;
    uint8_t properties[] = {0x78, 9};
    m.properties = (struct iovec){properties, sizeof(properties)};
    xqc_test_relay_input(up->request->stream, &m, XQC_MOQT_MSG_TRACK_STATUS);
    CU_ASSERT_TRUE(down->responded);
    CU_ASSERT_TRUE(down->stream->tx_fin);
    m = xqc_test_relay_message(XQC_MOQT_MSG_TRACK_STATUS);
    down = xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    record = xqc_test_relay_record(f.relay, down);
    CU_ASSERT(record->deadline > 0);
    xqc_moqt_relay_process(f.relay, record->deadline);
    CU_ASSERT_EQUAL(down->error.code, XQC_MOQT_REQUEST_TIMEOUT);
    /* A graceful source end propagates after the last upstream delivery. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    xqc_moqt_request_t *live = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_test_relay_establish(f.relay);
    record = xqc_test_relay_record(f.relay, live);
    CU_ASSERT_PTR_NOT_NULL_FATAL(record->selected);
    xqc_moqt_stream_t *pending = xqc_moqt_subgroup_open(live->subscription,
        0, 0, XQC_MOQT_DEFAULT_PRIORITY, XQC_FALSE, XQC_FALSE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(pending);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_PUBLISH_DONE;
    m.error.code = XQC_MOQT_PUBLISH_TRACK_ENDED;
    xqc_test_relay_input(record->selected->request->stream, &m,
                         XQC_MOQT_MSG_SUBSCRIBE);
    CU_ASSERT_TRUE(record->ending);
    xqc_usec_t next = xqc_moqt_relay_process(f.relay,
                                             xqc_monotonic_timestamp());
    CU_ASSERT(next > 0 && next <= record->deadline);
    CU_ASSERT_TRUE(record->ending);
    CU_ASSERT_FALSE(live->done_sent);
    CU_ASSERT_EQUAL(xqc_moqt_stream_finish(pending), XQC_OK);
    xqc_moqt_relay_process(f.relay, xqc_monotonic_timestamp());
    CU_ASSERT_TRUE(live->done_sent);
    /* Delivery is retained until the native FIN/ACK lifetime completes. */
    CU_ASSERT_PTR_NOT_NULL(live->subscription);
    xqc_moqt_stream_callbacks.stream_close_notify(pending->transport_stream,
                                                  pending);
    CU_ASSERT_PTR_NULL(live->subscription);

    /* A blocked final count has a deadline and cannot retain a fake grant. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    live = xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_test_relay_establish(f.relay);
    record = xqc_test_relay_record(f.relay, live);
    pending = xqc_moqt_subgroup_open(live->subscription, 0, 0,
        XQC_MOQT_DEFAULT_PRIORITY, XQC_FALSE, XQC_FALSE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(pending);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_PUBLISH_DONE;
    m.error.code = XQC_MOQT_PUBLISH_TRACK_ENDED;
    xqc_test_relay_input(record->selected->request->stream, &m,
                         XQC_MOQT_MSG_SUBSCRIBE);
    xqc_moqt_relay_process(f.relay, record->deadline);
    CU_ASSERT_TRUE(record->stopped);
    CU_ASSERT_TRUE(live->failed);
    CU_ASSERT_EQUAL(live->error.code, XQC_MOQT_RESET_TOO_FAR_BEHIND);
    CU_ASSERT_FALSE(live->stream->session->closed);
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_updates(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(
        XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_moqt_request_t *namespace = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    xqc_moqt_request_t *other_namespace = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_OTHER_PUBLISHER], &m);
    m.type = XQC_MOQT_MSG_SUBSCRIBE;
    xqc_moqt_request_t *down = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_moqt_request_t *healthy = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER], &m);
    xqc_test_relay_establish(f.relay);
    xqc_moqt_relay_request_t *record = xqc_test_relay_record(f.relay, down);
    /* Section 7.4: a state notification retains its individual grant. */
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY;
    uint8_t notify_location[] = {10, 20};
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(notify_location),
        notify_location};
    xqc_test_relay_input(record->selected->request->stream, &m,
                         XQC_MOQT_MSG_SUBSCRIBE);
    CU_ASSERT_EQUAL(down->subscription->track->largest.group_id, 10);
    CU_ASSERT_FALSE(healthy->subscription->track->has_largest);
    uint8_t paused = 0;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    m.request_id = f.peers[XQC_TEST_RELAY_SUBSCRIBER].next_request;
    f.peers[XQC_TEST_RELAY_SUBSCRIBER].next_request += XQC_MOQT_REQUEST_ID_STEP;
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, 1, &paused};
    xqc_test_relay_input(down->stream, &m, XQC_MOQT_MSG_SUBSCRIBE);
    CU_ASSERT_EQUAL(record->pending, 2);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_OK;
    uint8_t largest[] = {1, 2};
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
    for (xqc_moqt_relay_request_t *up = f.relay->requests; up; up = up->next) {
        if (up->parent == record && up->waiting_update) {
            xqc_test_relay_input(up->request->stream, &m,
                                 XQC_MOQT_MSG_REQUEST_UPDATE);
            m.type = XQC_MOQT_MSG_REQUEST_ERROR;
            m.error.code = XQC_MOQT_REQUEST_NOT_SUPPORTED;
            m.parameter_count = 0;
        }
    }
    CU_ASSERT_EQUAL(record->pending, 0);
    CU_ASSERT_FALSE(record->waiting_update);
    CU_ASSERT_FALSE(record->stopped);
    CU_ASSERT_FALSE(down->subscription->forward);
    CU_ASSERT_TRUE(healthy->subscription->forward);

    /* Existing grants survive namespace withdrawal; new routes do not. */
    xqc_moqt_request_cancel(namespace, XQC_MOQT_RESET_CANCELLED);
    xqc_moqt_request_cancel(other_namespace, XQC_MOQT_RESET_CANCELLED);
    xqc_moqt_stream_callbacks.stream_close_notify(
        namespace->stream->transport_stream, namespace->stream);
    xqc_moqt_stream_callbacks.stream_close_notify(
        other_namespace->stream->transport_stream, other_namespace->stream);
    /* A direct Track grant is independent of namespace registration. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_PUBLISH);
    m.track_name = (struct iovec){(void *)"direct", 6};
    m.track_alias = 42;
    xqc_moqt_request_t *publish = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    xqc_moqt_relay_request_t *source = xqc_test_relay_record(f.relay, publish);
    CU_ASSERT_TRUE(source->upstream);
    CU_ASSERT_FALSE(source->registered);
    CU_ASSERT_TRUE(source->waiting_update);
    xqc_moqt_message_t response;
    xqc_memzero(&response, sizeof(response));
    response.type = XQC_MOQT_MSG_REQUEST_OK;
    xqc_test_relay_input(publish->stream, &response, XQC_MOQT_MSG_PUBLISH);
    CU_ASSERT_FALSE(source->forward);
    xqc_moqt_location_t location;
    CU_ASSERT_EQUAL(xqc_moqt_subscription_largest(NULL, &location), XQC_ERROR);
    CU_ASSERT_EQUAL(xqc_moqt_subscription_largest(publish->subscription, NULL),
                    XQC_ERROR);
    CU_ASSERT_EQUAL(xqc_moqt_subscription_largest(publish->subscription,
                                                  &location), XQC_ERROR);
    m.type = XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY;
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(notify_location),
        notify_location};
    xqc_test_relay_input(publish->stream, &m, XQC_MOQT_MSG_PUBLISH);
    m.type = XQC_MOQT_MSG_SUBSCRIBE;
    m.parameter_count = 0;
    xqc_moqt_request_t *direct = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_TRUE(direct->established);
    CU_ASSERT_EQUAL(direct->subscription->track->largest.group_id, 10);
    CU_ASSERT_EQUAL(direct->subscription->track->largest.object_id, 20);
    CU_ASSERT_TRUE(source->waiting_update);
    xqc_test_relay_input(publish->stream, &response, XQC_MOQT_MSG_PUBLISH);
    CU_ASSERT_TRUE(source->forward);

    /* Section 9.10: live notifications cannot cancel an independent FETCH. */
    m.type = XQC_MOQT_MSG_FETCH;
    xqc_moqt_request_t *history = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER], &m);
    xqc_moqt_relay_request_t *history_record =
        xqc_test_relay_record(f.relay, history);
    xqc_moqt_relay_request_t *history_up = f.relay->requests;
    CU_ASSERT_PTR_EQUAL_FATAL(history_up->parent, history_record);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_FETCH_OK;
    m.end_group = 1;
    m.end_object = 2;
    xqc_test_relay_input(history_up->request->stream, &m, XQC_MOQT_MSG_FETCH);
    CU_ASSERT_TRUE(history_record->established);
    CU_ASSERT_FALSE(history_record->stopped);
    m.type = XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY;
    m.parameter_count = 1;
    notify_location[1]++;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(notify_location),
        notify_location};
    xqc_test_relay_input(publish->stream, &m, XQC_MOQT_MSG_PUBLISH);
    CU_ASSERT_EQUAL(direct->subscription->track->largest.object_id, 21);
    CU_ASSERT_FALSE(history_record->stopped);
    CU_ASSERT_FALSE(history->failed);

    /* A FETCH neither keeps live FORWARD enabled nor ends with its source. */
    xqc_moqt_subscription_cancel(direct->subscription,
                                 XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_TRUE(source->waiting_update);
    xqc_test_relay_input(publish->stream, &response, XQC_MOQT_MSG_PUBLISH);
    CU_ASSERT_FALSE(source->forward);
    m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    m.track_name = (struct iovec){(void *)"direct", 6};
    direct = xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_TRUE(direct->established);
    xqc_test_relay_input(publish->stream, &response, XQC_MOQT_MSG_PUBLISH);
    xqc_moqt_subscription_cancel(publish->subscription,
                                 XQC_MOQT_RESET_CANCELLED);
    CU_ASSERT_TRUE(direct->failed);
    CU_ASSERT_FALSE(history_record->stopped);
    CU_ASSERT_FALSE(history->failed);
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_limits(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    /* Equal binary names in different scopes never share a Track. */
    f.peers[XQC_TEST_RELAY_OTHER_PUBLISHER].peer->scope->data[0] = 'x';
    f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER].peer->scope->data[0] = 'x';
    xqc_moqt_message_t m = xqc_test_relay_message(
        XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_OTHER_PUBLISHER], &m);
    m.type = XQC_MOQT_MSG_SUBSCRIBE;
    xqc_moqt_request_t *down = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_moqt_request_t *other = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER], &m);
    xqc_test_relay_establish(f.relay);
    xqc_moqt_relay_request_t *a = xqc_test_relay_record(f.relay, down);
    xqc_moqt_relay_request_t *b = xqc_test_relay_record(f.relay, other);
    CU_ASSERT_PTR_NOT_EQUAL(a->track, b->track);
    CU_ASSERT_PTR_EQUAL(a->selected->peer,
                        f.peers[XQC_TEST_RELAY_PUBLISHER].peer);
    CU_ASSERT_PTR_EQUAL(b->selected->peer,
                        f.peers[XQC_TEST_RELAY_OTHER_PUBLISHER].peer);

    size_t original_bytes = f.relay->config.max_bytes;
    f.relay->config.max_bytes = f.relay->stats.bytes;
    m = xqc_test_relay_message(XQC_MOQT_MSG_TRACK_STATUS);
    xqc_moqt_request_t *limited = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_EQUAL(limited->error.code, XQC_MOQT_REQUEST_EXCESSIVE_LOAD);
    CU_ASSERT_FALSE(down->subscription->stopped);
    f.relay->config.max_bytes = original_bytes;
    size_t original_requests = f.relay->config.max_requests;
    f.relay->config.max_requests = f.relay->stats.requests;
    limited = xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_EQUAL(limited->error.code, XQC_MOQT_REQUEST_EXCESSIVE_LOAD);
    f.relay->config.max_requests = original_requests;

    /* MAX_CACHE_DURATION is measured from the first received object byte. */
    uint8_t properties[] = {0x0b, 2, 4, 0};
    xqc_moqt_message_t response;
    xqc_memzero(&response, sizeof(response));
    response.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    response.properties = (struct iovec){properties, sizeof(properties)};
    xqc_moqt_relay_buffer_free(f.relay, a->selected->response);
    a->selected->response = xqc_moqt_relay_message_copy(f.relay, &response,
                                                        XQC_MOQT_MSG_SUBSCRIBE);
    uint8_t body = 42;
    xqc_moqt_object_t object;
    xqc_memzero(&object, sizeof(object));
    object.group_id = 1;
    object.first_in_subgroup = 1;
    object.payload_length = 1;
    object.payload = (struct iovec){&body, sizeof(body)};
    xqc_stream_t *native = xqc_create_stream_with_conn(
        f.peers[XQC_TEST_RELAY_PUBLISHER].conn,
        XQC_CLI_UNI + XQC_TEST_RELAY_STREAM_ID_STEP, XQC_CLI_UNI, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(native);
    xqc_moqt_stream_t *input = native->user_data;
    uint8_t wire[128];
    uint64_t flags = XQC_MOQT_SUBGROUP_FIXED_BITS
        | XQC_MOQT_SUBGROUP_PROPERTIES | XQC_MOQT_SUBGROUP_EXPLICIT_ID
        | XQC_MOQT_SUBGROUP_FIRST_OBJECT;
    xqc_int_t n = xqc_moqt_subgroup_header_encode(
        a->selected->subscription->track_alias, flags, &object, wire,
        sizeof(wire));
    CU_ASSERT(n > 0);
    n += xqc_moqt_object_header_encode(flags, NULL, &object, wire + n,
                                       sizeof(wire) - n);
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(input, wire, n, 0), XQC_OK);
    input->state.data.object_time = xqc_monotonic_timestamp() - 1;
    CU_ASSERT_EQUAL(xqc_moqt_stream_input(input, &body, sizeof(body), 1),
                    XQC_OK);
    CU_ASSERT_EQUAL(f.relay->stats.expired, 1);
    CU_ASSERT_EQUAL(f.relay->stats.forwarded, 0);
    CU_ASSERT_FALSE(a->stopped);
    CU_ASSERT_FALSE(b->stopped);
    /* A Datagram that cannot be queued stops only the slow destination. */
    xqc_moqt_session_t *slow = b->peer->session;
    slow->config.max_buffered_bytes = slow->buffered_bytes;
    object.datagram = 1;
    object.first_in_subgroup = 0;
    n = xqc_moqt_datagram_encode(b->selected->subscription->track_alias,
                                 &object, wire, sizeof(wire));
    CU_ASSERT(n > 0);
    xqc_moqt_datagram_input(b->selected->peer->session, wire, n);
    CU_ASSERT_TRUE(b->stopped);
    CU_ASSERT_FALSE(a->stopped);
    CU_ASSERT_EQUAL(f.relay->stats.slow_subscribers, 1);
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_fill(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(
        XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    /* Nested timeout and absolute range, independent of the live filter. */
    uint8_t fill[] = {8, 0x0a, 0, 0x17, 4, 1, 0, 0, 2};
    m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FILL_PARAMETERS, sizeof(fill), fill};
    uint8_t largest[] = {1, 2};
    xqc_moqt_message_t response;
    xqc_memzero(&response, sizeof(response));
    response.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    response.parameter_count = 1;
    response.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
    xqc_moqt_request_t *down = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_moqt_relay_request_t *up = f.relay->requests;
    CU_ASSERT_TRUE(up->upstream);
    xqc_test_relay_input(up->request->stream, &response, up->type);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f.relay->fetches);
    xqc_moqt_relay_fetch_t *zero = f.relay->fetches;
    CU_ASSERT_PTR_NULL(zero->upstream);
    CU_ASSERT_EQUAL(zero->deadline, 0);
    CU_ASSERT_TRUE(zero->closed);
    CU_ASSERT_PTR_NULL(zero->stream);
    xqc_moqt_stream_t *output = down->stream->session->streams;
    while (output != NULL && output->kind != XQC_MOQT_STREAM_FETCH) {
        output = output->next;
    }
    CU_ASSERT_PTR_NOT_NULL_FATAL(output);
    CU_ASSERT_TRUE(output->tx_fin);
    CU_ASSERT_FALSE(output->state.data.has_error);
    CU_ASSERT_EQUAL(output->state.data.object.range, XQC_MOQT_RANGE_TIMEOUT);
    CU_ASSERT_FALSE(down->subscription->stopped);

    fill[2] = 100;
    down = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER], &m);
    up = f.relay->requests;
    xqc_test_relay_input(up->request->stream, &response, up->type);
    xqc_moqt_relay_fetch_t *fetch = f.relay->fetches;
    CU_ASSERT_PTR_NOT_EQUAL(fetch, zero);
    CU_ASSERT_PTR_NOT_NULL_FATAL(fetch->upstream);
    CU_ASSERT_EQUAL(fetch->upstream->type, XQC_MOQT_MSG_FETCH);
    xqc_usec_t deadline = fetch->deadline;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    m.request_id = f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER].next_request;
    uint8_t forward = 1;
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, 1, &forward};
    xqc_test_relay_input(down->stream, &m, XQC_MOQT_MSG_SUBSCRIBE);
    CU_ASSERT_EQUAL(fetch->deadline, deadline);
    CU_ASSERT_FALSE(fetch->upstream->waiting_update);
    response.type = XQC_MOQT_MSG_REQUEST_OK;
    xqc_test_relay_input(up->request->stream, &response,
                         XQC_MOQT_MSG_REQUEST_UPDATE);
    CU_ASSERT_FALSE(fetch->closed);
    xqc_memzero(&response, sizeof(response));
    response.type = XQC_MOQT_MSG_REQUEST_ERROR;
    response.error.code = XQC_MOQT_REQUEST_TIMEOUT;
    xqc_test_relay_input(fetch->upstream->request->stream, &response,
                         XQC_MOQT_MSG_FETCH);
    CU_ASSERT_TRUE(fetch->closed);
    CU_ASSERT_FALSE(down->subscription->stopped);
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_late_response(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(
        XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_OTHER_PUBLISHER], &m);
    m.type = XQC_MOQT_MSG_SUBSCRIBE;
    xqc_moqt_request_t *down = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_moqt_relay_request_t *first = f.relay->requests;
    xqc_moqt_relay_request_t *late = first->next;
    CU_ASSERT_TRUE_FATAL(first->upstream && late->upstream);
    xqc_moqt_relay_request_t *record = first->parent;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    m.track_alias = 42;
    xqc_test_relay_input(first->request->stream, &m, first->type);
    CU_ASSERT_TRUE(down->established);
    CU_ASSERT_FALSE(late->established);

    uint8_t forward = 0;
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    m.request_id = f.peers[XQC_TEST_RELAY_SUBSCRIBER].next_request;
    f.peers[XQC_TEST_RELAY_SUBSCRIBER].next_request += XQC_MOQT_REQUEST_ID_STEP;
    m.parameter_count = 1;
    m.parameters[0] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FORWARD, 1, &forward};
    xqc_test_relay_input(down->stream, &m, XQC_MOQT_MSG_SUBSCRIBE);
    CU_ASSERT_EQUAL(record->pending, 2);
    CU_ASSERT_FALSE(late->waiting_update);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    m.track_alias = 42;
    xqc_test_relay_input(late->request->stream, &m, late->type);
    CU_ASSERT_TRUE(late->waiting_update);
    CU_ASSERT_EQUAL(record->pending, 2);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_OK;
    xqc_test_relay_input(first->request->stream, &m,
                         XQC_MOQT_MSG_REQUEST_UPDATE);
    CU_ASSERT_TRUE(record->waiting_update);
    xqc_test_relay_input(late->request->stream, &m,
                         XQC_MOQT_MSG_REQUEST_UPDATE);
    CU_ASSERT_EQUAL(record->pending, 0);
    CU_ASSERT_FALSE(record->waiting_update);
    CU_ASSERT_FALSE(down->subscription->forward);

    /* A late initial rejection must not invalidate an existing grant. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    down = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER], &m);
    first = f.relay->requests;
    late = first->next;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    m.track_alias = 44;
    xqc_test_relay_input(first->request->stream, &m, first->type);
    m.type = XQC_MOQT_MSG_REQUEST_ERROR;
    m.error.code = XQC_MOQT_REQUEST_UNAUTHORIZED;
    xqc_test_relay_input(late->request->stream, &m, late->type);
    CU_ASSERT_TRUE(down->established);
    CU_ASSERT_FALSE(down->subscription->stopped);
    /* Revoked outgoing authorization on a late source cannot stall FIFO. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    down = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    first = f.relay->requests;
    late = first->next;
    record = first->parent;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    m.track_alias = 46;
    xqc_test_relay_input(first->request->stream, &m, first->type);
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    m.request_id = f.peers[XQC_TEST_RELAY_SUBSCRIBER].next_request;
    f.peers[XQC_TEST_RELAY_SUBSCRIBER].next_request += XQC_MOQT_REQUEST_ID_STEP;
    xqc_test_relay_input(down->stream, &m, XQC_MOQT_MSG_SUBSCRIBE);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_OK;
    xqc_test_relay_input(first->request->stream, &m,
                         XQC_MOQT_MSG_REQUEST_UPDATE);
    CU_ASSERT_EQUAL(record->pending, 1);
    xqc_test_relay_peer_t *publisher = late->peer->user_data;
    publisher->forward_denied = XQC_TRUE;
    m.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    m.track_alias = 46;
    xqc_test_relay_input(late->request->stream, &m, late->type);
    CU_ASSERT_TRUE(late->stopped);
    CU_ASSERT_EQUAL(record->pending, 0);
    CU_ASSERT_FALSE(record->waiting_update);
    CU_ASSERT_FALSE(record->stopped);
    CU_ASSERT_TRUE(down->subscription->forward);
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_fill_boundaries(void)
{
    enum { XQC_TEST_FILL_SHORTENED, XQC_TEST_FILL_LIMIT, XQC_TEST_FILL_RESET };
    /* Each Fill has its own promised range and cancellation scope. */
    for (xqc_int_t scenario = XQC_TEST_FILL_SHORTENED;
         scenario <= XQC_TEST_FILL_RESET; scenario++)
    {
        xqc_test_relay_t f;
        xqc_test_relay_init(&f);
        xqc_moqt_message_t m = xqc_test_relay_message(
            XQC_MOQT_MSG_PUBLISH_NAMESPACE);
        xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
        uint8_t fill[] = {8, 0x0a, 100, 0x17, 4, 1, 0, 0, 2};
        m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_FILL_PARAMETERS, sizeof(fill), fill};
        xqc_moqt_request_t *down = xqc_test_relay_receive(
            &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
        xqc_moqt_relay_request_t *up = f.relay->requests;
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
        uint8_t largest[] = {1, 2};
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_LARGEST_OBJECT, sizeof(largest), largest};
        xqc_test_relay_input(up->request->stream, &m, up->type);
        xqc_moqt_relay_fetch_t *fetch = f.relay->fetches;
        CU_ASSERT_PTR_NOT_NULL_FATAL(fetch);
        CU_ASSERT_PTR_NOT_NULL_FATAL(fetch->upstream);
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_FETCH_OK;
        m.end_group = 1;
        m.end_object = scenario == XQC_TEST_FILL_SHORTENED ? 1 : 2;
        xqc_test_relay_input(fetch->upstream->request->stream, &m,
                             XQC_MOQT_MSG_FETCH);
        if (scenario == XQC_TEST_FILL_SHORTENED) {
            /* A source cannot shorten the already promised Fill snapshot. */
            CU_ASSERT_TRUE(fetch->closed);
            CU_ASSERT_FALSE(down->subscription->stopped);
            xqc_test_relay_destroy(&f);
            continue;
        }
        CU_ASSERT_FALSE(fetch->closed);
        CU_ASSERT_PTR_NOT_NULL_FATAL(fetch->input);
        if (scenario == XQC_TEST_FILL_LIMIT) {
            f.relay->config.max_streams = f.relay->stats.streams;
        }
        xqc_stream_t *native = xqc_create_stream_with_conn(
            f.peers[XQC_TEST_RELAY_PUBLISHER].conn,
            XQC_CLI_UNI + XQC_TEST_RELAY_STREAM_ID_STEP,
            XQC_CLI_UNI, NULL, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(native);
        uint8_t wire[128];
        xqc_int_t n = xqc_vi64_write(wire, wire + sizeof(wire),
                                     XQC_MOQT_FETCH_STREAM);
        n += xqc_vi64_write(wire + n, wire + sizeof(wire),
                            xqc_moqt_fetch_info(fetch->input)->request_id);
        xqc_moqt_object_t object;
        xqc_memzero(&object, sizeof(object));
        object.group_id = 1;
        object.priority = XQC_MOQT_DEFAULT_PRIORITY;
        object.payload_length = 1;
        xqc_moqt_fetch_history_t history;
        xqc_memzero(&history, sizeof(history));
        xqc_int_t length = xqc_moqt_fetch_header_encode(
            xqc_moqt_fetch_info(fetch->input)->group_order, &history,
            &object, wire + n, sizeof(wire) - n);
        CU_ASSERT(length > 0);
        n += length;
        wire[n++] = 42;
        CU_ASSERT_EQUAL(xqc_moqt_stream_input(native->user_data, wire, n, 0),
                        XQC_OK);
        if (scenario == XQC_TEST_FILL_LIMIT) {
            CU_ASSERT_TRUE(fetch->closed);
            CU_ASSERT_EQUAL(f.relay->stats.forwarded, 0);
        } else {
            CU_ASSERT_EQUAL(f.relay->stats.forwarded, 1);
            xqc_moqt_stream_cancel(native->user_data,
                                   XQC_MOQT_RESET_DELIVERY_TIMEOUT);
            CU_ASSERT_TRUE(fetch->closed);
        }
        CU_ASSERT_FALSE(down->subscription->stopped);
        xqc_test_relay_destroy(&f);
    }
}

void
xqc_test_moqt_relay_tracks(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(
        XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_OTHER_PUBLISHER], &m);
    m.type = XQC_MOQT_MSG_SUBSCRIBE_TRACKS;
    xqc_moqt_request_t *watch = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER], &m);
    size_t sources = 0;
    for (xqc_moqt_relay_request_t *q = f.relay->requests; q; q = q->next) {
        if (q->upstream && q->type == XQC_MOQT_MSG_SUBSCRIBE_TRACKS) {
            sources++;
            xqc_moqt_message_t response;
            xqc_memzero(&response, sizeof(response));
            response.type = XQC_MOQT_MSG_REQUEST_OK;
            xqc_test_relay_input(q->request->stream, &response, q->type);
            CU_ASSERT_TRUE(q->established);
            CU_ASSERT_PTR_NULL(q->parent);
        }
    }
    CU_ASSERT_EQUAL(sources, 2);
    m = xqc_test_relay_message(XQC_MOQT_MSG_PUBLISH);
    m.track_alias = 42;
    xqc_moqt_request_t *publisher = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    xqc_moqt_relay_request_t *source =
        xqc_test_relay_record(f.relay, publisher);
    xqc_moqt_relay_request_t *publications[2];
    size_t count = 0;
    for (xqc_moqt_relay_request_t *q = f.relay->requests; q; q = q->next) {
        if (!q->upstream && q->type == XQC_MOQT_MSG_PUBLISH) {
            CU_ASSERT(count < 2);
            if (count < 2) {
                publications[count++] = q;
            }
            CU_ASSERT_PTR_NULL(q->parent);
            CU_ASSERT_PTR_EQUAL(q->selected, source);
            xqc_moqt_message_t response;
            xqc_memzero(&response, sizeof(response));
            response.type = XQC_MOQT_MSG_REQUEST_OK;
            xqc_test_relay_input(q->request->stream, &response, q->type);
        }
    }
    CU_ASSERT_EQUAL_FATAL(count, 2);
    xqc_moqt_request_cancel(watch, XQC_MOQT_RESET_CANCELLED);
    xqc_moqt_stream_callbacks.stream_close_notify(
        watch->stream->transport_stream, watch->stream);
    xqc_moqt_relay_process(f.relay, xqc_monotonic_timestamp());
    CU_ASSERT_FALSE(publications[0]->stopped);
    CU_ASSERT_FALSE(publications[1]->stopped);
    uint8_t payload = 42;
    xqc_moqt_object_t object;
    xqc_memzero(&object, sizeof(object));
    object.group_id = 1;
    object.datagram = 1;
    object.payload = (struct iovec){&payload, sizeof(payload)};
    object.payload_length = sizeof(payload);
    xqc_moqt_relay_object(source->subscription, NULL, &object, source->peer);
    CU_ASSERT_EQUAL(f.relay->stats.forwarded, 2);
    xqc_moqt_subscription_cancel(publications[0]->subscription,
                                 XQC_MOQT_RESET_CANCELLED);
    object.group_id++;
    xqc_moqt_relay_object(source->subscription, NULL, &object, source->peer);
    CU_ASSERT_EQUAL(f.relay->stats.forwarded, 3);
    CU_ASSERT_FALSE(publications[1]->stopped);
    /* An established downstream Pc must not become a publisher route. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    xqc_moqt_request_t *subscriber = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_PTR_EQUAL(xqc_test_relay_record(f.relay, subscriber)->selected,
                        source);
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_rendezvous_tracks(void)
{
    enum { XQC_TEST_ST_FIRST, XQC_TEST_SUB_FIRST, XQC_TEST_CANCEL,
           XQC_TEST_TIMEOUT, XQC_TEST_SCENARIOS };
    for (size_t scenario = 0; scenario < XQC_TEST_SCENARIOS; scenario++) {
        xqc_test_relay_t f;
        xqc_test_relay_init(&f);
        xqc_test_relay_peer_t *subscriber =
            &f.peers[XQC_TEST_RELAY_SUBSCRIBER];
        xqc_moqt_message_t m = xqc_test_relay_message(
            XQC_MOQT_MSG_SUBSCRIBE_TRACKS);
        xqc_moqt_request_t *watch = NULL;
        if (scenario != XQC_TEST_SUB_FIRST) {
            watch = xqc_test_relay_receive(subscriber, &m);
        }
        xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_OTHER_SUBSCRIBER], &m);
        m.type = XQC_MOQT_MSG_SUBSCRIBE;
        uint8_t wait[] = {100};
        m.parameter_count = 1;
        m.parameters[0] = (xqc_moq_message_parameter_t){
            XQC_MOQT_PARAM_RENDEZVOUS_TIMEOUT, sizeof(wait), wait};
        xqc_moqt_request_t *pending = xqc_test_relay_receive(subscriber, &m);
        CU_ASSERT_FALSE(pending->established);
        CU_ASSERT_FALSE(pending->failed);
        if (watch == NULL) {
            m.type = XQC_MOQT_MSG_SUBSCRIBE_TRACKS;
            m.parameter_count = 0;
            watch = xqc_test_relay_receive(subscriber, &m);
        }
        if (scenario == XQC_TEST_CANCEL) {
            xqc_moqt_request_cancel(pending, XQC_MOQT_RESET_CANCELLED);
        } else if (scenario == XQC_TEST_TIMEOUT) {
            xqc_moqt_relay_request_t *down = xqc_test_relay_record(
                f.relay, pending);
            xqc_moqt_relay_process(f.relay, down->deadline);
            CU_ASSERT_EQUAL(pending->error.code, XQC_MOQT_REQUEST_TIMEOUT);
        }
        xqc_bool_t cancelled = scenario == XQC_TEST_CANCEL
                               || scenario == XQC_TEST_TIMEOUT;
        m = xqc_test_relay_message(XQC_MOQT_MSG_PUBLISH);
        m.track_alias = 42;
        xqc_moqt_request_t *publish = xqc_test_relay_receive(
            &f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
        CU_ASSERT_EQUAL(pending->established, !cancelled);
        CU_ASSERT_FALSE(xqc_list_empty(&watch->publications));
        size_t publications = 0;
        for (xqc_moqt_relay_request_t *q = f.relay->requests; q; q = q->next) {
            if (q->upstream || q->type != XQC_MOQT_MSG_PUBLISH) {
                continue;
            }
            if (q->peer == subscriber->peer) {
                CU_ASSERT_TRUE(cancelled);
            }
            publications++;
            xqc_moqt_message_t response;
            xqc_memzero(&response, sizeof(response));
            response.type = XQC_MOQT_MSG_REQUEST_OK;
            xqc_test_relay_input(q->request->stream, &response, q->type);
        }
        CU_ASSERT_EQUAL(publications, 1 + cancelled);
        /* Section 7.6: each peer receives the object exactly once. */
        uint8_t payload = 42;
        xqc_moqt_object_t object;
        xqc_memzero(&object, sizeof(object));
        object.group_id = 1;
        object.datagram = 1;
        object.payload = (struct iovec){&payload, sizeof(payload)};
        object.payload_length = sizeof(payload);
        xqc_moqt_relay_request_t *source = xqc_test_relay_record(f.relay,
                                                                 publish);
        xqc_moqt_relay_object(source->subscription, NULL, &object,
                              source->peer);
        CU_ASSERT_EQUAL(f.relay->stats.forwarded, 2);
        if (!cancelled) {
            xqc_moqt_request_cancel(pending, XQC_MOQT_RESET_CANCELLED);
        }
        size_t requests = f.relay->stats.requests;
        xqc_moqt_relay_routes(f.relay);
        CU_ASSERT_EQUAL(f.relay->stats.requests, requests);
        /* Section 3.6.3: only a new publication instance may create Pc. */
        xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_OTHER_PUBLISHER], &m);
        CU_ASSERT_EQUAL(f.relay->stats.requests, requests + 3);
        xqc_test_relay_destroy(&f);
    }
}

void
xqc_test_moqt_relay_tracks_errors(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(
        XQC_MOQT_MSG_SUBSCRIBE_TRACKS);
    xqc_moqt_request_t *watch = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    f.peers[XQC_TEST_RELAY_SUBSCRIBER].forward_denied = 1;
    m.type = XQC_MOQT_MSG_PUBLISH;
    m.track_alias = 42;
    xqc_moqt_request_t *publish = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    xqc_moqt_relay_request_t *source = xqc_test_relay_record(f.relay, publish);
    uint64_t first_instance = source->publication_id;
    CU_ASSERT_TRUE(xqc_list_empty(&watch->publications));
    f.peers[XQC_TEST_RELAY_SUBSCRIBER].forward_denied = 0;
    xqc_moqt_session_t *session = watch->stream->session;
    size_t max_streams = session->config.max_streams;
    session->config.max_streams = session->stream_count;
    xqc_moqt_relay_routes(f.relay);
    CU_ASSERT_FALSE(xqc_list_empty(&watch->publications));
    CU_ASSERT_PTR_EQUAL(f.relay->requests, source);
    session->config.max_streams = max_streams;
    xqc_moqt_relay_routes(f.relay);
    /* Section 3.6.3: new credit cannot retry the skipped instance. */
    CU_ASSERT_PTR_EQUAL(f.relay->requests, source);
    xqc_moqt_request_cancel(publish, XQC_MOQT_RESET_CANCELLED);
    m.track_alias++;
    publish = xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    source = xqc_test_relay_record(f.relay, publish);
    CU_ASSERT(source->publication_id > first_instance);
    CU_ASSERT_FALSE(f.relay->requests->upstream);
    CU_ASSERT_PTR_EQUAL(f.relay->requests->selected, source);
    /* Do not advertise an originating subscriber's own Track back to it. */
    m.type = XQC_MOQT_MSG_SUBSCRIBE_TRACKS;
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    for (xqc_moqt_relay_request_t *q = f.relay->requests; q; q = q->next) {
        if (!q->upstream && q->type == XQC_MOQT_MSG_PUBLISH) {
            CU_ASSERT_PTR_NOT_EQUAL(q->peer, source->peer);
        }
    }
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_discovery_updates(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(
        XQC_MOQT_MSG_PUBLISH_NAMESPACE);
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    m.type = XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE;
    m.track_namespace.count = 0;
    xqc_moqt_request_t *namespaces = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    CU_ASSERT_FALSE(xqc_list_empty(&namespaces->namespaces));
    m.type = XQC_MOQT_MSG_SUBSCRIBE_TRACKS;
    xqc_moqt_request_t *watch = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_moqt_relay_request_t *up = f.relay->requests;
    CU_ASSERT_EQUAL_FATAL(up->type, XQC_MOQT_MSG_SUBSCRIBE_TRACKS);
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_OK;
    xqc_test_relay_input(up->request->stream, &m, up->type);

    /* Section 3.6.3: propagate a source skip without creating a fake Pc. */
    m = xqc_test_relay_message(XQC_MOQT_MSG_PUBLISH_SKIPPED);
    size_t requests = f.relay->stats.requests;
    xqc_test_relay_input(up->request->stream, &m, up->type);
    CU_ASSERT_FALSE(xqc_list_empty(&watch->publications));
    CU_ASSERT_EQUAL(f.relay->stats.requests, requests);
    CU_ASSERT_FALSE(watch->failed);

    /* Namespace and Track-interest updates retain their own lifetimes. */
    xqc_moqt_request_t *interests[] = {namespaces, watch};
    for (size_t i = 0; i < sizeof(interests) / sizeof(interests[0]); i++) {
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
        m.request_id = f.peers[XQC_TEST_RELAY_SUBSCRIBER].next_request;
        f.peers[XQC_TEST_RELAY_SUBSCRIBER].next_request
            += XQC_MOQT_REQUEST_ID_STEP;
        xqc_moqt_relay_request_t *q = xqc_test_relay_record(f.relay,
                                                            interests[i]);
        xqc_test_relay_input(interests[i]->stream, &m, q->type);
        CU_ASSERT_FALSE(q->waiting_update);
        CU_ASSERT_PTR_NULL(q->candidate);
        CU_ASSERT_FALSE(q->stopped);
    }
    /* Instance exhaustion cancels only the upstream enumeration. */
    f.relay->next_publication = UINT64_MAX;
    m = xqc_test_relay_message(XQC_MOQT_MSG_PUBLISH_SKIPPED);
    m.track_name = (struct iovec){(void *)"next", 4};
    xqc_test_relay_input(up->request->stream, &m, up->type);
    CU_ASSERT_TRUE(up->request->failed);
    CU_ASSERT_FALSE(watch->failed);
    CU_ASSERT_FALSE(namespaces->failed);
    m = xqc_test_relay_message(XQC_MOQT_MSG_PUBLISH);
    xqc_moqt_request_t *overflow = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    CU_ASSERT_EQUAL(overflow->error.code, XQC_MOQT_REQUEST_EXCESSIVE_LOAD);
    xqc_test_relay_destroy(&f);
}

void
xqc_test_moqt_relay_budget_rollback(void)
{
    xqc_test_relay_t f;
    xqc_test_relay_init(&f);
    xqc_moqt_message_t m = xqc_test_relay_message(XQC_MOQT_MSG_SUBSCRIBE);
    size_t state = sizeof(xqc_var_buf_t)
        + xqc_moqt_message_encode(&m, 0, NULL, 0);
    size_t name = sizeof(xqc_var_buf_t)
        + xqc_moqt_name_encode(&m.track_namespace, &m.track_name, NULL, 0);
    size_t budgets[] = {
        sizeof(xqc_moqt_relay_request_t),
        sizeof(xqc_moqt_relay_request_t) + state,
        sizeof(xqc_moqt_relay_request_t) + state + name,
        sizeof(xqc_moqt_relay_request_t) + state + name
            + sizeof(xqc_moqt_relay_track_t),
    };
    size_t initial = f.relay->stats.bytes;
    size_t limit = f.relay->config.max_bytes;
    for (size_t i = 0; i < sizeof(budgets) / sizeof(budgets[0]); i++) {
        f.relay->config.max_bytes = initial + budgets[i];
        xqc_moqt_request_t *request = xqc_test_relay_receive(
            &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
        CU_ASSERT_EQUAL(request->error.code, XQC_MOQT_REQUEST_EXCESSIVE_LOAD);
        CU_ASSERT_EQUAL(f.relay->stats.bytes, initial);
        CU_ASSERT_PTR_NULL(f.relay->tracks);
        CU_ASSERT_EQUAL(f.relay->stats.requests, 0);
    }
    f.relay->config.max_bytes = limit;
    m.type = XQC_MOQT_MSG_PUBLISH_NAMESPACE;
    xqc_test_relay_receive(&f.peers[XQC_TEST_RELAY_PUBLISHER], &m);
    m.type = XQC_MOQT_MSG_SUBSCRIBE;
    xqc_moqt_request_t *request = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_test_relay_establish(f.relay);
    CU_ASSERT_TRUE(request->established);
    /* Saving an upstream grant must be atomic under the metadata budget. */
    xqc_moqt_request_t *limited = xqc_test_relay_receive(
        &f.peers[XQC_TEST_RELAY_SUBSCRIBER], &m);
    xqc_moqt_relay_request_t *up = f.relay->requests;
    f.relay->config.max_bytes = f.relay->stats.bytes;
    xqc_moqt_message_t response;
    xqc_memzero(&response, sizeof(response));
    response.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    response.track_alias = 42;
    xqc_test_relay_input(up->request->stream, &response, up->type);
    CU_ASSERT_TRUE(up->stopped);
    CU_ASSERT_TRUE(limited->failed);
    CU_ASSERT_FALSE(request->subscription->stopped);
    f.relay->config.max_bytes = limit;

    /* Reject a peer if there is no room for the required update credit. */
    xqc_moqt_config_t config;
    xqc_moqt_config_init(&config, XQC_MOQT_VERSION_DRAFT_22);
    xqc_moqt_kv_t options[XQC_MOQT_MAX_OPTIONS];
    xqc_memzero(options, sizeof(options));
    for (size_t i = 0; i < XQC_MOQT_MAX_OPTIONS; i++) {
        options[i].type = XQC_MOQT_OPT_MAX_REQUEST_UPDATES + 1 + i;
    }
    config.setup_options = options;
    config.setup_option_count = XQC_MOQT_MAX_OPTIONS;
    struct iovec scope = {(void *)"example/moq", 11};
    initial = f.relay->stats.bytes;
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_peer_create(f.relay, NULL, &config,
                                                  &scope, NULL));
    CU_ASSERT_EQUAL(f.relay->stats.bytes, initial);
    config.setup_option_count = 1;
    options[0].type = XQC_MOQT_OPT_MAX_REQUEST_UPDATES;
    CU_ASSERT_PTR_NULL(xqc_moqt_relay_peer_create(f.relay, NULL, &config,
                                                  &scope, NULL));
    CU_ASSERT_EQUAL(f.relay->stats.bytes, initial);
    f.relay->config.max_bytes = f.relay->stats.bytes;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_UPDATE;
    m.request_id = f.peers[XQC_TEST_RELAY_SUBSCRIBER].next_request;
    xqc_test_relay_input(request->stream, &m, XQC_MOQT_MSG_SUBSCRIBE);
    CU_ASSERT_EQUAL(request->error.code, XQC_MOQT_REQUEST_EXCESSIVE_LOAD);
    CU_ASSERT_PTR_NULL(xqc_test_relay_record(f.relay, request)->candidate);
    CU_ASSERT_FALSE(request->stream->session->closed);
    f.relay->config.max_bytes = limit;
    xqc_test_relay_destroy(&f);
}
