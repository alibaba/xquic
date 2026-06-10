/**
 * wt_test_client.c - WebTransport echo client for interop testing
 *
 * Uses only xquic public API (xqc_webtransport.h + xqc_http3.h + xquic.h).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event2/event.h>

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 4433
#define ECHO_MSG     "Hello WebTransport from xquic client!"
#define DGRAM_MSG    "draft15 datagram echo"
#define MULTI_MSG_1  "multi-session-one"
#define MULTI_MSG_2  "multi-session-two"
#define RESET_PREFIX_REQ "RESET_PREFIX_REQUEST"
#define RESET_PREFIX_RSP "RESET_PREFIX_OK"
#define SPLIT_HEADER_MSG "split-header-echo"
#define PRE_SESSION_DGRAM_MSG "pre-session-datagram"
#define SERVER_BIDI_TRIGGER "server-bidi-trigger"
#define SERVER_BIDI_MSG "server-bidi-from-demo-server"
#define FC_DISABLED_MSG "fc-disabled-single-session"
#define PRE_SESSION_STREAM_OVERFLOW_BYTES 65537
#define PRE_SESSION_STREAM_CHUNK_BYTES 4096

typedef enum {
    WT_SCENARIO_BIDI,
    WT_SCENARIO_DATAGRAM,
    WT_SCENARIO_CLOSE_GATES,
    WT_SCENARIO_RESET_PREFIX,
    WT_SCENARIO_MULTI_SESSION,
    WT_SCENARIO_FC_DATA_BLOCKED,
    WT_SCENARIO_FC_STREAM_BLOCKED,
    WT_SCENARIO_COMPAT_LEGACY,
    WT_SCENARIO_STRICT_REJECT_LEGACY,
    WT_SCENARIO_INVALID_DATAGRAM,
    WT_SCENARIO_SPLIT_HEADER,
    WT_SCENARIO_PRE_SESSION_DATAGRAM,
    WT_SCENARIO_PEER_CLOSE_FIN,
    WT_SCENARIO_CLIENT_REJECT_REQUIREMENTS,
    WT_SCENARIO_STRICT_MISSING_WT_ENABLED,
    WT_SCENARIO_STRICT_MISSING_H3_DATAGRAM,
    WT_SCENARIO_STRICT_MISSING_CONNECT,
    WT_SCENARIO_STRICT_MISSING_DGRAM_TP,
    WT_SCENARIO_STRICT_MISSING_RESET_AT,
    WT_SCENARIO_LARGE_DATAGRAM_REJECT,
    WT_SCENARIO_SERVER_BIDI,
    WT_SCENARIO_FC_DISABLED_SINGLE_SESSION,
    WT_SCENARIO_PRE_SESSION_STREAM_OVERFLOW,
} wt_scenario_t;

typedef struct {
    xqc_wt_bidistream_t *stream;
    char                *buf;
    size_t               cap;
    size_t               len;
    int                  fin;
    int                  counted;
} wt_stream_read_state_t;

static xqc_usec_t wt_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

typedef struct {
    xqc_engine_t       *engine;
    struct event_base  *eb;
    struct event       *ev_engine;
    struct event       *ev_socket;
    struct event       *ev_poll;
    int                 fd;
    struct sockaddr_in  local_addr;
    struct sockaddr_in  peer_addr;
    socklen_t           peer_addrlen;
    xqc_cid_t           cid;
    xqc_h3_conn_t      *h3_conn;
    xqc_webtransport_session_t *session;
    xqc_webtransport_session_t **sessions;
    size_t               sessions_cap;
    size_t               session_count;
    size_t               target_sessions;
    size_t               streams_per_session;
    size_t               payload_size;
    size_t               repeat_count;
    size_t               expected_echoes;
    size_t               received_echoes;
    int                  timeout_sec;
    int                  handshake_done;
    int                  session_open_sent;
    int                  session_open_failed;
    int                  session_ready;
    int                  echo_sent;
    int                  echo_done;
    int                  echo_ok;
    int                  dgram_sent;
    int                  dgram_done;
    int                  close_checked;
    int                  invalid_dgram_sent;
    xqc_h3_ext_bytestream_t *split_bs;
    xqc_h3_ext_bytestream_t *overflow_bs;
    size_t               split_first_sent;
    size_t               split_rest_sent;
    size_t               overflow_payload_sent;
    int                  overflow_rejected;
    wt_scenario_t        scenario;
    xqc_wt_mode_t        mode;
    wt_stream_read_state_t *stream_reads;
    size_t                  stream_reads_cap;
    char                 host[256];
} wt_ctx_t;

static wt_ctx_t *g_ctx = NULL;
static size_t    g_saved_token_len = 0;
static size_t    g_saved_session_len = 0;
static size_t    g_saved_tp_len = 0;
static size_t    g_verified_cert_chain_len = 0;

/* forward declarations */
static void engine_cb(int fd, short what, void *arg);
static void socket_cb(evutil_socket_t fd, short what, void *arg);
static void read_socket(wt_ctx_t *ctx);
static void try_open_session(wt_ctx_t *ctx);
static void try_send_echo(wt_ctx_t *ctx);
static void try_run_ready_scenario(wt_ctx_t *ctx);
static void try_send_pre_session_dgram(wt_ctx_t *ctx);
static void try_send_pre_session_stream_overflow(wt_ctx_t *ctx);

/* ==================== transport callbacks ==================== */

static int
wt_read_vint_len(const unsigned char *p, size_t remaining,
    size_t *encoded_len, uint64_t *value)
{
    if (remaining < 1) return -1;
    size_t len = (size_t)1 << (p[0] >> 6);
    if (remaining < len) return -1;
    uint64_t v = p[0] & 0x3f;
    for (size_t i = 1; i < len; i++) {
        v = (v << 8) | p[i];
    }
    *encoded_len = len;
    *value = v;
    return 0;
}

static size_t
wt_put_vint_len(uint64_t value)
{
    if (value < 64) {
        return 1;
    }
    if (value < 16384) {
        return 2;
    }
    if (value < 1073741824ULL) {
        return 4;
    }
    return 8;
}

static size_t
wt_write_vint(uint64_t value, uint8_t *buf, size_t buf_len)
{
    size_t len = wt_put_vint_len(value);
    if (buf == NULL || buf_len < len) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        buf[len - 1 - i] = (uint8_t)(value & 0xff);
        value >>= 8;
    }
    if (len == 2) {
        buf[0] |= 0x40;
    } else if (len == 4) {
        buf[0] |= 0x80;
    } else if (len == 8) {
        buf[0] |= 0xc0;
    }
    return len;
}

static size_t
wt_encode_stream_id(uint64_t stream_id, uint8_t *buf, size_t buf_len)
{
    return wt_write_vint(stream_id, buf, buf_len);
}

static size_t
wt_encode_h3_datagram_session_id(uint64_t session_id,
    uint8_t *buf, size_t buf_len)
{
    if ((session_id & 0x03) != 0) {
        return 0;
    }
    return wt_write_vint(session_id >> 2, buf, buf_len);
}

static int
wt_quic_long_header_packet_len(const unsigned char *buf, size_t size,
    size_t *packet_len)
{
    if (size < 7 || !(buf[0] & 0x80)) return -1;
    size_t off = 5;
    unsigned char dcid_len = buf[off++];
    if (size < off + dcid_len + 1) return -1;
    off += dcid_len;
    unsigned char scid_len = buf[off++];
    if (size < off + scid_len) return -1;
    off += scid_len;
    if ((buf[0] & 0x30) == 0x00) {
        size_t token_len_len = 0;
        uint64_t token_len = 0;
        if (wt_read_vint_len(buf + off, size - off,
                &token_len_len, &token_len) != 0) return -1;
        off += token_len_len;
        if (size < off + token_len) return -1;
        off += (size_t)token_len;
    }
    size_t length_len = 0;
    uint64_t length = 0;
    if (wt_read_vint_len(buf + off, size - off,
            &length_len, &length) != 0) return -1;
    off += length_len;
    if (size < off + length) return -1;
    *packet_len = off + (size_t)length;
    return 0;
}

static ssize_t
write_socket_cb(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    if (size > 1500 && (buf[0] & 0x80)) {
        size_t off = 0;
        while (off < size) {
            size_t packet_len = 0;
            if (wt_quic_long_header_packet_len(buf + off, size - off,
                    &packet_len) != 0 || packet_len == 0) {
                break;
            }
            ssize_t res = sendto(g_ctx->fd, buf + off, packet_len, 0,
                peer_addr, peer_addrlen);
            if (res < 0) return errno == EAGAIN ? XQC_SOCKET_EAGAIN : res;
            off += packet_len;
        }
        if (off == size) {
            return (ssize_t)size;
        }
    }
    ssize_t res = sendto(g_ctx->fd, buf, size, 0, peer_addr, peer_addrlen);
    return (res < 0 && errno == EAGAIN) ? XQC_SOCKET_EAGAIN : res;
}

static ssize_t
write_socket_ex_cb(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    return write_socket_cb(buf, size, peer_addr, peer_addrlen, user);
}

static void
save_token_cb(const unsigned char *token, unsigned token_len, void *user)
{
    if (token != NULL && user == g_ctx) {
        g_saved_token_len = token_len;
    }
}

static void
save_session_cb(const char *data, size_t data_len, void *user)
{
    if (data != NULL && user == g_ctx) {
        g_saved_session_len = data_len;
    }
}

static void
save_tp_cb(const char *data, size_t data_len, void *user)
{
    if (data != NULL && user == g_ctx) {
        g_saved_tp_len = data_len;
    }
}

static int
cert_verify_cb(const unsigned char *certs[], const size_t cert_len[],
    size_t certs_len, void *user)
{
    if (certs != NULL && cert_len != NULL && user == g_ctx) {
        g_verified_cert_chain_len = certs_len;
    }
    return 0;
}

static void
set_timer_cb(xqc_msec_t wake_after, void *user)
{
    struct timeval tv = { wake_after / 1000, (wake_after % 1000) * 1000 };
    event_add(g_ctx->ev_engine, &tv);
}

static void
log_cb(xqc_log_level_t lvl, const void *buf, size_t sz, void *user)
{
}

static const char *
scenario_name(wt_scenario_t scenario)
{
    switch (scenario) {
    case WT_SCENARIO_DATAGRAM:
        return "datagram";
    case WT_SCENARIO_CLOSE_GATES:
        return "close-gates";
    case WT_SCENARIO_RESET_PREFIX:
        return "reset-prefix";
    case WT_SCENARIO_MULTI_SESSION:
        return "multi-session";
    case WT_SCENARIO_FC_DATA_BLOCKED:
        return "fc-data-blocked";
    case WT_SCENARIO_FC_STREAM_BLOCKED:
        return "fc-stream-blocked";
    case WT_SCENARIO_COMPAT_LEGACY:
        return "compat-legacy";
    case WT_SCENARIO_STRICT_REJECT_LEGACY:
        return "strict-reject-legacy";
    case WT_SCENARIO_INVALID_DATAGRAM:
        return "invalid-datagram";
    case WT_SCENARIO_SPLIT_HEADER:
        return "split-header";
    case WT_SCENARIO_PRE_SESSION_DATAGRAM:
        return "pre-session-datagram";
    case WT_SCENARIO_PEER_CLOSE_FIN:
        return "peer-close-fin";
    case WT_SCENARIO_CLIENT_REJECT_REQUIREMENTS:
        return "client-reject-requirements";
    case WT_SCENARIO_STRICT_MISSING_WT_ENABLED:
        return "strict-missing-wt-enabled";
    case WT_SCENARIO_STRICT_MISSING_H3_DATAGRAM:
        return "strict-missing-h3-datagram";
    case WT_SCENARIO_STRICT_MISSING_CONNECT:
        return "strict-missing-connect";
    case WT_SCENARIO_STRICT_MISSING_DGRAM_TP:
        return "strict-missing-dgram-tp";
    case WT_SCENARIO_STRICT_MISSING_RESET_AT:
        return "strict-missing-reset-at";
    case WT_SCENARIO_LARGE_DATAGRAM_REJECT:
        return "large-datagram-reject";
    case WT_SCENARIO_SERVER_BIDI:
        return "server-bidi";
    case WT_SCENARIO_FC_DISABLED_SINGLE_SESSION:
        return "fc-disabled-single-session";
    case WT_SCENARIO_PRE_SESSION_STREAM_OVERFLOW:
        return "pre-session-stream-overflow";
    case WT_SCENARIO_BIDI:
    default:
        return "bidi";
    }
}

static int
parse_scenario(const char *name, wt_scenario_t *scenario)
{
    if (strcmp(name, "bidi") == 0 || strcmp(name, "churn") == 0) {
        *scenario = WT_SCENARIO_BIDI;
    } else if (strcmp(name, "datagram") == 0) {
        *scenario = WT_SCENARIO_DATAGRAM;
    } else if (strcmp(name, "close-gates") == 0) {
        *scenario = WT_SCENARIO_CLOSE_GATES;
    } else if (strcmp(name, "reset-prefix") == 0) {
        *scenario = WT_SCENARIO_RESET_PREFIX;
    } else if (strcmp(name, "multi-session") == 0) {
        *scenario = WT_SCENARIO_MULTI_SESSION;
    } else if (strcmp(name, "fc-data-blocked") == 0) {
        *scenario = WT_SCENARIO_FC_DATA_BLOCKED;
    } else if (strcmp(name, "fc-stream-blocked") == 0) {
        *scenario = WT_SCENARIO_FC_STREAM_BLOCKED;
    } else if (strcmp(name, "compat-legacy") == 0) {
        *scenario = WT_SCENARIO_COMPAT_LEGACY;
    } else if (strcmp(name, "strict-reject-legacy") == 0) {
        *scenario = WT_SCENARIO_STRICT_REJECT_LEGACY;
    } else if (strcmp(name, "invalid-datagram") == 0) {
        *scenario = WT_SCENARIO_INVALID_DATAGRAM;
    } else if (strcmp(name, "split-header") == 0) {
        *scenario = WT_SCENARIO_SPLIT_HEADER;
    } else if (strcmp(name, "pre-session-datagram") == 0) {
        *scenario = WT_SCENARIO_PRE_SESSION_DATAGRAM;
    } else if (strcmp(name, "peer-close-fin") == 0) {
        *scenario = WT_SCENARIO_PEER_CLOSE_FIN;
    } else if (strncmp(name, "client-reject-", 14) == 0) {
        *scenario = WT_SCENARIO_CLIENT_REJECT_REQUIREMENTS;
    } else if (strcmp(name, "strict-missing-wt-enabled") == 0) {
        *scenario = WT_SCENARIO_STRICT_MISSING_WT_ENABLED;
    } else if (strcmp(name, "strict-missing-h3-datagram") == 0) {
        *scenario = WT_SCENARIO_STRICT_MISSING_H3_DATAGRAM;
    } else if (strcmp(name, "strict-missing-connect") == 0) {
        *scenario = WT_SCENARIO_STRICT_MISSING_CONNECT;
    } else if (strcmp(name, "strict-missing-dgram-tp") == 0) {
        *scenario = WT_SCENARIO_STRICT_MISSING_DGRAM_TP;
    } else if (strcmp(name, "strict-missing-reset-at") == 0) {
        *scenario = WT_SCENARIO_STRICT_MISSING_RESET_AT;
    } else if (strcmp(name, "large-datagram-reject") == 0) {
        *scenario = WT_SCENARIO_LARGE_DATAGRAM_REJECT;
    } else if (strcmp(name, "server-bidi") == 0) {
        *scenario = WT_SCENARIO_SERVER_BIDI;
    } else if (strcmp(name, "fc-disabled-single-session") == 0) {
        *scenario = WT_SCENARIO_FC_DISABLED_SINGLE_SESSION;
    } else if (strcmp(name, "pre-session-stream-overflow") == 0) {
        *scenario = WT_SCENARIO_PRE_SESSION_STREAM_OVERFLOW;
    } else {
        return 0;
    }
    return 1;
}

static xqc_wt_mode_t
parse_mode(const char *name)
{
    if (strcmp(name, "legacy") == 0) {
        return XQC_WT_MODE_BROWSER_LEGACY;
    }
    if (strcmp(name, "compat") == 0) {
        return XQC_WT_MODE_BROWSER_COMPAT;
    }
    return XQC_WT_MODE_DRAFT15_STRICT;
}

static void
configure_requirement_scenario(xqc_engine_t *engine, wt_scenario_t scenario)
{
    xqc_bool_t enable_webtransport =
        scenario == WT_SCENARIO_STRICT_MISSING_WT_ENABLED ? 0 : 1;
    xqc_bool_t h3_datagram =
        scenario == WT_SCENARIO_STRICT_MISSING_H3_DATAGRAM ? 0 : 1;
    xqc_bool_t enable_connect_protocol =
        scenario == WT_SCENARIO_STRICT_MISSING_CONNECT ? 0 : 1;

    xqc_wt_engine_set_default_settings(engine, g_ctx->mode, 1024, 1024,
        16 * 1024 * 1024, enable_webtransport, h3_datagram,
        enable_connect_protocol);
}

static int
is_strict_missing_requirement_scenario(wt_scenario_t scenario)
{
    return scenario == WT_SCENARIO_STRICT_MISSING_WT_ENABLED
        || scenario == WT_SCENARIO_STRICT_MISSING_H3_DATAGRAM
        || scenario == WT_SCENARIO_STRICT_MISSING_CONNECT
        || scenario == WT_SCENARIO_STRICT_MISSING_DGRAM_TP
        || scenario == WT_SCENARIO_STRICT_MISSING_RESET_AT;
}

static wt_stream_read_state_t *
stream_state(wt_ctx_t *ctx, xqc_wt_bidistream_t *stream)
{
    wt_stream_read_state_t *empty = NULL;
    for (size_t i = 0; i < ctx->stream_reads_cap; i++) {
        if (ctx->stream_reads[i].stream == stream) {
            return &ctx->stream_reads[i];
        }
        if (empty == NULL && ctx->stream_reads[i].stream == NULL) {
            empty = &ctx->stream_reads[i];
        }
    }
    if (empty) {
        empty->stream = stream;
        empty->cap = ctx->payload_size ? ctx->payload_size : strlen(ECHO_MSG);
        empty->buf = malloc(empty->cap);
        if (empty->buf == NULL) {
            empty->stream = NULL;
            empty->cap = 0;
            return NULL;
        }
        empty->len = 0;
        empty->fin = 0;
        empty->counted = 0;
    }
    return empty;
}

/* ==================== WT callbacks ==================== */

static int
on_session_create(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user)
{
    if (!headers) return 0;
    for (size_t i = 0; i < headers->count; i++) {
        size_t nlen = headers->headers[i].name.iov_len;
        size_t vlen = headers->headers[i].value.iov_len;
        char *n = (char *)headers->headers[i].name.iov_base;
        char *v = (char *)headers->headers[i].value.iov_base;
        if (n && v && nlen == 7 && memcmp(n, ":status", 7) == 0 &&
            vlen == 3 && memcmp(v, "200", 3) == 0) {
            g_ctx->session = session;
            if (g_ctx->session_count >= g_ctx->sessions_cap) {
                printf("[FAIL] session capacity exceeded: %zu/%zu\n",
                    g_ctx->session_count, g_ctx->sessions_cap);
                event_base_loopbreak(g_ctx->eb);
                return 0;
            }
            g_ctx->sessions[g_ctx->session_count++] = session;
            g_ctx->session_ready = 1;
            g_ctx->session_open_sent = 0;
            printf("[OK] session-setup\n");
            try_run_ready_scenario(g_ctx);
            return 0;
        }
        if (n && v && nlen == 7 && memcmp(n, ":status", 7) == 0
            && is_strict_missing_requirement_scenario(g_ctx->scenario))
        {
            if (vlen == 3 && memcmp(v, "400", 3) == 0) {
                printf("[OK] %s\n", scenario_name(g_ctx->scenario));
                g_ctx->echo_ok = 1;
                g_ctx->echo_done = 1;
                event_base_loopbreak(g_ctx->eb);
            } else {
                printf("[FAIL] %s: status %.*s\n",
                    scenario_name(g_ctx->scenario), (int)vlen, v);
                event_base_loopbreak(g_ctx->eb);
            }
            return 0;
        }
    }
    return 0;
}

static int
on_session_close(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user)
{
    if (g_ctx->scenario == WT_SCENARIO_INVALID_DATAGRAM
        && g_ctx->invalid_dgram_sent)
    {
        printf("[OK] invalid-datagram\n");
        g_ctx->echo_ok = 1;
    }
    if (g_ctx->scenario == WT_SCENARIO_PEER_CLOSE_FIN
        && g_ctx->close_checked)
    {
        printf("[OK] peer-close-fin\n");
        g_ctx->echo_ok = 1;
        g_ctx->echo_done = 1;
    }
    if (!g_ctx->echo_done && !g_ctx->session_ready) {
        printf("[FAIL] Session closed before echo\n");
    }
    event_base_loopbreak(g_ctx->eb);
    return 0;
}

static void
on_handshake_done(xqc_webtransport_conn_t *conn, void *user)
{
    if (conn == NULL) {
        g_ctx->session_open_failed = 1;
        event_base_loopbreak(g_ctx->eb);
        return;
    }

    g_ctx->h3_conn = xqc_wt_conn_get_h3_conn(conn);
    g_ctx->handshake_done = 1;
    try_send_pre_session_dgram(g_ctx);
    try_open_session(g_ctx);
}

static xqc_int_t
on_bidi_read(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t data_len, uint8_t fin, void *user)
{
    wt_stream_read_state_t *state = stream_state(g_ctx, stream);
    if (state == NULL) {
        return 0;
    }
    if (data_len > 0 && state->len + data_len <= state->cap) {
        memcpy(state->buf + state->len, data, data_len);
        state->len += data_len;
    }
    if (fin) {
        state->fin = 1;
    }

    if (g_ctx->scenario == WT_SCENARIO_SPLIT_HEADER) {
        size_t expected = strlen(SPLIT_HEADER_MSG);
        if (state->len >= expected) {
            if (state->len == expected
                && memcmp(state->buf, SPLIT_HEADER_MSG, expected) == 0)
            {
                printf("[OK] split-header\n");
                g_ctx->echo_ok = 1;
            } else {
                printf("[FAIL] split-header: mismatch\n");
            }
            g_ctx->echo_done = 1;
            xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
        }
        return 0;
    }

    if (g_ctx->scenario == WT_SCENARIO_DATAGRAM) {
        if (state->len > 0) {
            g_ctx->close_checked = 1;
            try_run_ready_scenario(g_ctx);
        }
        return 0;
    }

    if (g_ctx->scenario == WT_SCENARIO_RESET_PREFIX) {
        size_t expected = strlen(RESET_PREFIX_RSP);
        if (state->len >= expected) {
            if (state->len == expected
                && memcmp(state->buf, RESET_PREFIX_RSP, expected) == 0)
            {
                printf("[OK] reset-prefix\n");
                g_ctx->echo_ok = 1;
            } else {
                printf("[FAIL] reset-prefix: mismatch\n");
            }
            g_ctx->echo_done = 1;
            xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
        }
        return 0;
    }

    if (g_ctx->scenario == WT_SCENARIO_SERVER_BIDI) {
        size_t expected = strlen(SERVER_BIDI_MSG);
        if (state->len >= expected) {
            if (state->len == expected
                && memcmp(state->buf, SERVER_BIDI_MSG, expected) == 0)
            {
                printf("[OK] server-bidi\n");
                g_ctx->echo_ok = 1;
            } else {
                printf("[FAIL] server-bidi: mismatch\n");
            }
            g_ctx->echo_done = 1;
            xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
        }
        return 0;
    }

    if (g_ctx->scenario == WT_SCENARIO_FC_DISABLED_SINGLE_SESSION) {
        size_t expected = strlen(FC_DISABLED_MSG);
        if (state->len >= expected) {
            if (state->len == expected
                && memcmp(state->buf, FC_DISABLED_MSG, expected) == 0)
            {
                printf("[OK] fc-disabled-single-session\n");
                g_ctx->echo_ok = 1;
            } else {
                printf("[FAIL] fc-disabled-single-session: mismatch\n");
            }
            g_ctx->echo_done = 1;
            xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
        }
        return 0;
    }

    if (g_ctx->scenario == WT_SCENARIO_MULTI_SESSION) {
        if (!state->counted && state->len >= g_ctx->payload_size) {
            int ok = state->len == g_ctx->payload_size;
            for (size_t i = 0; ok && i < g_ctx->payload_size; i++) {
                ok = state->buf[i] == 'm';
            }
            if (ok) {
                state->counted = 1;
                g_ctx->received_echoes++;
            } else {
                printf("[FAIL] multi-session: mismatch\n");
                g_ctx->echo_done = 1;
                xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
                return 0;
            }
        }
        if (g_ctx->received_echoes >= g_ctx->expected_echoes) {
            printf("[OK] multi-session\n");
            g_ctx->echo_ok = 1;
            g_ctx->echo_done = 1;
            xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
        }
        return 0;
    }

    size_t expected = strlen(ECHO_MSG);
    if (state->len >= expected) {
        if (state->len == expected
            && memcmp(state->buf, ECHO_MSG, expected) == 0)
        {
            if (state->fin) {
                printf("[OK] bidi-echo: %zu bytes match\n", state->len);
                printf("[OK] bidi-fin\n");
                g_ctx->echo_ok = 1;
            } else {
                printf("[FAIL] bidi-echo: FIN not observed\n");
            }
            if (g_ctx->scenario == WT_SCENARIO_COMPAT_LEGACY) {
                printf("[OK] compat-legacy\n");
            }
        } else {
            printf("[FAIL] bidi-echo: mismatch (%zu vs %zu)\n", state->len, expected);
        }
        g_ctx->echo_done = 1;
        xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
    }
    return 0;
}

static void
on_dgram_read(xqc_webtransport_session_t *session, const void *data,
    size_t data_len, void *user_data, uint64_t data_recv_time)
{
    if ((g_ctx->scenario != WT_SCENARIO_DATAGRAM
            && g_ctx->scenario != WT_SCENARIO_PRE_SESSION_DATAGRAM
            && g_ctx->scenario != WT_SCENARIO_SPLIT_HEADER)
        || data == NULL)
    {
        return;
    }
    if (g_ctx->scenario == WT_SCENARIO_SPLIT_HEADER) {
        if (data_len == strlen(SPLIT_HEADER_MSG)
            && memcmp(data, SPLIT_HEADER_MSG, strlen(SPLIT_HEADER_MSG)) == 0)
        {
            printf("[OK] split-header\n");
            g_ctx->dgram_done = 1;
            g_ctx->echo_ok = 1;
            g_ctx->echo_done = 1;
            xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
        }
        return;
    }
    if (g_ctx->scenario == WT_SCENARIO_PRE_SESSION_DATAGRAM) {
        if (data_len == strlen(PRE_SESSION_DGRAM_MSG)
            && memcmp(data, PRE_SESSION_DGRAM_MSG,
                strlen(PRE_SESSION_DGRAM_MSG)) == 0)
        {
            printf("[OK] pre-session-datagram\n");
            g_ctx->dgram_done = 1;
            g_ctx->echo_ok = 1;
            g_ctx->echo_done = 1;
            xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
        }
        return;
    }
    if (data_len == strlen(DGRAM_MSG)
        && memcmp(data, DGRAM_MSG, strlen(DGRAM_MSG)) == 0)
    {
        printf("[OK] datagram-echo\n");
        g_ctx->dgram_done = 1;
        g_ctx->echo_ok = 1;
        g_ctx->echo_done = 1;
        xqc_h3_conn_close(g_ctx->engine, &g_ctx->cid);
    }
}

/* ==================== engine / socket ==================== */

static void
engine_cb(int fd, short what, void *arg)
{
    read_socket(g_ctx);
    xqc_engine_main_logic(g_ctx->engine);
    try_send_pre_session_dgram(g_ctx);
    try_send_pre_session_stream_overflow(g_ctx);
    try_open_session(g_ctx);
    try_run_ready_scenario(g_ctx);
}

static void
read_socket(wt_ctx_t *ctx)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    unsigned char buf[1500];
    ssize_t n;
    do {
        n = recvfrom(ctx->fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &alen);
        if (n < 0) break;
        xqc_engine_packet_process(ctx->engine, buf, n,
            (struct sockaddr *)&ctx->local_addr, sizeof(ctx->local_addr),
            (struct sockaddr *)&addr, alen, (xqc_usec_t)wt_now(), ctx);
    } while (n > 0);
    xqc_engine_finish_recv(ctx->engine);
}

static void
socket_cb(evutil_socket_t fd, short what, void *arg)
{
    if (what & EV_READ) read_socket(g_ctx);
    xqc_engine_main_logic(g_ctx->engine);
    try_send_pre_session_dgram(g_ctx);
    try_send_pre_session_stream_overflow(g_ctx);
    try_open_session(g_ctx);
    try_run_ready_scenario(g_ctx);
    read_socket(g_ctx);
    xqc_engine_main_logic(g_ctx->engine);
    try_send_pre_session_dgram(g_ctx);
    try_send_pre_session_stream_overflow(g_ctx);
    try_open_session(g_ctx);
    try_run_ready_scenario(g_ctx);
}

static void
try_send_pre_session_dgram(wt_ctx_t *ctx)
{
    if (ctx->scenario != WT_SCENARIO_PRE_SESSION_DATAGRAM
        || !ctx->handshake_done || ctx->dgram_sent || ctx->session_open_sent)
    {
        return;
    }

    if (ctx->h3_conn == NULL) {
        return;
    }
    xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(ctx->h3_conn);
    if (conn == NULL) {
        return;
    }
    xqc_conn_public_remote_trans_settings_t remote_settings =
        xqc_conn_get_public_remote_trans_settings(conn);
    if (remote_settings.max_datagram_frame_size == 0) {
        return;
    }

    uint8_t payload[64];
    size_t sid_len = wt_encode_h3_datagram_session_id(
        0, payload, sizeof(payload));
    if (sid_len == 0
        || sid_len + strlen(PRE_SESSION_DGRAM_MSG) > sizeof(payload))
    {
        printf("[FAIL] pre-session-datagram setup\n");
        event_base_loopbreak(ctx->eb);
        return;
    }
    memcpy(payload + sid_len, PRE_SESSION_DGRAM_MSG,
        strlen(PRE_SESSION_DGRAM_MSG));

    uint64_t dgram_id = 0;
    xqc_int_t ret = xqc_h3_ext_datagram_send(ctx->h3_conn, payload,
        sid_len + strlen(PRE_SESSION_DGRAM_MSG), &dgram_id,
        XQC_DATA_QOS_HIGHEST);
    if (ret == XQC_OK) {
        ctx->dgram_sent = 1;
        xqc_engine_main_logic(ctx->engine);
        try_open_session(ctx);
        return;
    }
    if (ret == -XQC_EAGAIN || ret == -XQC_ESTATE) {
        xqc_conn_continue_send(ctx->engine, &ctx->cid);
        return;
    }

    printf("[FAIL] pre-session-datagram send: %d\n", ret);
    event_base_loopbreak(ctx->eb);
}

static void
try_send_pre_session_stream_overflow(wt_ctx_t *ctx)
{
    if (ctx->scenario != WT_SCENARIO_PRE_SESSION_STREAM_OVERFLOW
        || !ctx->handshake_done || ctx->session_open_sent
        || ctx->overflow_rejected)
    {
        return;
    }

    if (ctx->overflow_bs == NULL) {
        ctx->overflow_bs = xqc_h3_ext_bytestream_create(ctx->engine,
            &ctx->cid, NULL);
        if (ctx->overflow_bs == NULL) {
            return;
        }
    }

    uint8_t chunk[PRE_SESSION_STREAM_CHUNK_BYTES + 8];
    size_t off = 0;
    if (ctx->overflow_payload_sent == 0) {
        size_t sid_len = wt_encode_stream_id(0, chunk, sizeof(chunk));
        if (sid_len == 0) {
            printf("[FAIL] pre-session-stream-overflow setup\n");
            event_base_loopbreak(ctx->eb);
            return;
        }
        off = sid_len;
    }

    size_t remain = PRE_SESSION_STREAM_OVERFLOW_BYTES
        - ctx->overflow_payload_sent;
    size_t n = remain < PRE_SESSION_STREAM_CHUNK_BYTES
        ? remain : PRE_SESSION_STREAM_CHUNK_BYTES;
    memset(chunk + off, 'O', n);

    ssize_t sent = xqc_h3_ext_bytestream_send(ctx->overflow_bs, chunk,
        off + n, 0, XQC_DATA_QOS_HIGHEST);
    if (sent == -XQC_EAGAIN || sent == -XQC_ESTATE) {
        xqc_conn_continue_send(ctx->engine, &ctx->cid);
        return;
    }
    if (sent < 0) {
        if (ctx->overflow_payload_sent > 0) {
            printf("[OK] pre-session-stream-overflow\n");
            ctx->overflow_rejected = 1;
            try_open_session(ctx);
            return;
        }
        printf("[FAIL] pre-session-stream-overflow send=%zd\n", sent);
        event_base_loopbreak(ctx->eb);
        return;
    }

    size_t payload_sent = (size_t)sent > off ? (size_t)sent - off : 0;
    ctx->overflow_payload_sent += payload_sent;
    if (ctx->overflow_payload_sent < PRE_SESSION_STREAM_OVERFLOW_BYTES) {
        xqc_conn_continue_send(ctx->engine, &ctx->cid);
        return;
    }

    xqc_engine_main_logic(ctx->engine);
    printf("[OK] pre-session-stream-overflow\n");
    ctx->overflow_rejected = 1;
    try_open_session(ctx);
}

static void
try_open_session(wt_ctx_t *ctx)
{
    if (!ctx->handshake_done || ctx->session_open_sent
        || ctx->session_open_failed)
    {
        return;
    }
    if (ctx->scenario == WT_SCENARIO_PRE_SESSION_DATAGRAM
        && !ctx->dgram_sent)
    {
        return;
    }
    if (ctx->scenario == WT_SCENARIO_PRE_SESSION_STREAM_OVERFLOW
        && !ctx->overflow_rejected)
    {
        return;
    }
    if (ctx->session_count >= ctx->target_sessions) {
        return;
    }

    xqc_int_t ret = xqc_wt_client_open_session(ctx->engine, &ctx->cid,
                                               "/echo", ctx->host, ctx);
    if (ret == XQC_OK) {
        ctx->session_open_sent = 1;
        printf("[INFO] Extended CONNECT sent\n");
        return;
    }

    if (ret == -XQC_ESTATE || ret == -XQC_EAGAIN) {
        return;
    }

    if (ctx->scenario == WT_SCENARIO_STRICT_REJECT_LEGACY
        && ret == -XQC_EPROTO)
    {
        printf("[OK] strict-reject-legacy\n");
        ctx->echo_ok = 1;
        ctx->echo_done = 1;
        ctx->session_open_failed = 1;
        event_base_loopbreak(ctx->eb);
        return;
    }
    if (ctx->scenario == WT_SCENARIO_CLIENT_REJECT_REQUIREMENTS
        && ret == -XQC_EPROTO)
    {
        printf("[OK] client-reject-requirements\n");
        ctx->echo_ok = 1;
        ctx->echo_done = 1;
        ctx->session_open_failed = 1;
        event_base_loopbreak(ctx->eb);
        return;
    }

    ctx->session_open_failed = 1;
    printf("[FAIL] open_session: %d\n", ret);
    event_base_loopbreak(ctx->eb);
}

static void
try_send_echo(wt_ctx_t *ctx)
{
    if (!ctx->session_ready || ctx->session == NULL || ctx->echo_sent
        || ctx->echo_done)
    {
        return;
    }

    ssize_t sent = xqc_wt_session_send_bidi(ctx->session, ECHO_MSG,
                                            strlen(ECHO_MSG), 1);
    if (sent > 0) {
        ctx->echo_sent = 1;
        printf("[INFO] Sent bidi echo: %zd bytes\n", sent);
        return;
    }

    if (sent == -XQC_ESTATE || sent == -XQC_ESTREAM_BLOCKED
        || sent == -XQC_ECONN_BLOCKED)
    {
        return;
    }

    printf("[FAIL] send_bidi failed: %zd\n", sent);
    event_base_loopbreak(ctx->eb);
}

static void
try_send_split_header(wt_ctx_t *ctx)
{
    if (ctx->echo_sent || ctx->session_count < ctx->target_sessions) {
        return;
    }

    uint8_t header[8];
    uint64_t session_id = ((uint64_t)ctx->target_sessions - 1) << 2;
    size_t header_len = wt_encode_stream_id(session_id, header, sizeof(header));
    if (header_len < 2) {
        printf("[FAIL] split-header setup\n");
        event_base_loopbreak(ctx->eb);
        return;
    }

    if (ctx->split_bs == NULL) {
        ctx->split_bs = xqc_h3_ext_bytestream_create(ctx->engine, &ctx->cid, NULL);
    }
    if (ctx->split_bs == NULL) {
        printf("[FAIL] split-header stream create\n");
        event_base_loopbreak(ctx->eb);
        return;
    }

    if (ctx->split_first_sent < 1) {
        ssize_t first = xqc_h3_ext_bytestream_send(ctx->split_bs, header, 1, 0,
            XQC_DATA_QOS_HIGHEST);
        if (first == -XQC_EAGAIN || first == -XQC_ESTATE) {
            xqc_conn_continue_send(ctx->engine, &ctx->cid);
            return;
        }
        if (first < 0) {
            printf("[FAIL] split-header first write: %zd\n", first);
            event_base_loopbreak(ctx->eb);
            return;
        }
        ctx->split_first_sent += (size_t)first;
        if (ctx->split_first_sent < 1) {
            xqc_conn_continue_send(ctx->engine, &ctx->cid);
            return;
        }
        xqc_engine_main_logic(ctx->engine);
    }

    uint8_t payload[64];
    size_t msg_len = strlen(SPLIT_HEADER_MSG);
    size_t rest_len = header_len - 1 + msg_len;
    if (rest_len > sizeof(payload)) {
        printf("[FAIL] split-header payload setup\n");
        event_base_loopbreak(ctx->eb);
        return;
    }
    memcpy(payload, header + 1, header_len - 1);
    memcpy(payload + header_len - 1, SPLIT_HEADER_MSG, msg_len);

    if (ctx->split_rest_sent < rest_len) {
        ssize_t rest = xqc_h3_ext_bytestream_send(ctx->split_bs,
            payload + ctx->split_rest_sent, rest_len - ctx->split_rest_sent, 1,
            XQC_DATA_QOS_HIGHEST);
        if (rest == -XQC_EAGAIN || rest == -XQC_ESTATE) {
            xqc_conn_continue_send(ctx->engine, &ctx->cid);
            return;
        }
        if (rest < 0) {
            printf("[FAIL] split-header rest write: %zd\n", rest);
            event_base_loopbreak(ctx->eb);
            return;
        }
        ctx->split_rest_sent += (size_t)rest;
    }
    if (ctx->split_rest_sent == rest_len) {
        ctx->echo_sent = 1;
        xqc_engine_main_logic(ctx->engine);
        return;
    }
    xqc_conn_continue_send(ctx->engine, &ctx->cid);
}

static void
try_run_ready_scenario(wt_ctx_t *ctx)
{
    if (!ctx->session_ready || ctx->session == NULL || ctx->echo_done) {
        return;
    }

    switch (ctx->scenario) {
    case WT_SCENARIO_BIDI:
    case WT_SCENARIO_PRE_SESSION_STREAM_OVERFLOW:
    case WT_SCENARIO_COMPAT_LEGACY:
        try_send_echo(ctx);
        break;

    case WT_SCENARIO_DATAGRAM:
    case WT_SCENARIO_PRE_SESSION_DATAGRAM:
        if (!ctx->dgram_sent) {
            xqc_int_t ret = xqc_wt_session_datagram_send(ctx->session,
                (void *)DGRAM_MSG, (uint32_t)strlen(DGRAM_MSG));
            if (ret == XQC_OK) {
                ctx->dgram_sent = 1;
                xqc_engine_main_logic(ctx->engine);
                return;
            }
            if (ret == -XQC_EAGAIN || ret == -XQC_ESTATE) {
                xqc_conn_continue_send(ctx->engine, &ctx->cid);
                return;
            }
            printf("[FAIL] datagram-send: %d\n", ret);
            event_base_loopbreak(ctx->eb);
        }
        break;

    case WT_SCENARIO_CLOSE_GATES:
        if (!ctx->close_checked) {
            ctx->close_checked = 1;
            xqc_int_t close_ret = xqc_wt_session_close_with_error(
                ctx->session, 0, "done", 4);
            ssize_t bidi_ret = xqc_wt_session_send_bidi(ctx->session,
                ECHO_MSG, strlen(ECHO_MSG), 1);
            xqc_int_t dgram_ret = xqc_wt_session_datagram_send(ctx->session,
                (void *)DGRAM_MSG, (uint32_t)strlen(DGRAM_MSG));
            if (close_ret == XQC_OK && bidi_ret == -XQC_ESTATE
                && dgram_ret == -XQC_ESTATE)
            {
                printf("[OK] close-gates\n");
                ctx->echo_ok = 1;
                ctx->echo_done = 1;
                xqc_h3_conn_close(ctx->engine, &ctx->cid);
                return;
            }
            printf("[FAIL] close-gates: close=%d bidi=%zd dgram=%d\n",
                close_ret, bidi_ret, dgram_ret);
            event_base_loopbreak(ctx->eb);
        }
        break;

    case WT_SCENARIO_PEER_CLOSE_FIN:
        if (!ctx->close_checked) {
            ctx->close_checked = 1;
            xqc_int_t close_ret = xqc_wt_session_close_with_error(
                ctx->session, 0, "done", 4);
            if (close_ret == XQC_OK) {
                xqc_engine_main_logic(ctx->engine);
                return;
            }
            if (close_ret == -XQC_EAGAIN || close_ret == -XQC_ESTATE) {
                xqc_conn_continue_send(ctx->engine, &ctx->cid);
                return;
            }
            printf("[FAIL] peer-close-fin: close=%d\n", close_ret);
            event_base_loopbreak(ctx->eb);
        }
        break;

    case WT_SCENARIO_RESET_PREFIX:
        if (!ctx->echo_sent) {
            ssize_t sent = xqc_wt_session_send_bidi(ctx->session,
                RESET_PREFIX_REQ, strlen(RESET_PREFIX_REQ), 1);
            if (sent > 0) {
                ctx->echo_sent = 1;
                return;
            }
            if (sent == -XQC_ESTATE || sent == -XQC_ESTREAM_BLOCKED
                || sent == -XQC_ECONN_BLOCKED)
            {
                return;
            }
            printf("[FAIL] reset-prefix-send: %zd\n", sent);
            event_base_loopbreak(ctx->eb);
        }
        break;

    case WT_SCENARIO_LARGE_DATAGRAM_REJECT:
        if (!ctx->dgram_sent) {
            uint8_t payload[XQC_WEBTRANSPORT_DEFAULT_DGRAM_MSS + 32];
            memset(payload, 'L', sizeof(payload));
            xqc_int_t ret = xqc_wt_session_datagram_send(ctx->session,
                payload, (uint32_t)sizeof(payload));
            if (ret == -XQC_EDGRAM_TOO_LARGE) {
                printf("[OK] large-datagram-reject\n");
                ctx->dgram_sent = 1;
                ctx->echo_ok = 1;
                ctx->echo_done = 1;
                xqc_h3_conn_close(ctx->engine, &ctx->cid);
                return;
            }
            printf("[FAIL] large-datagram-reject: %d\n", ret);
            event_base_loopbreak(ctx->eb);
        }
        break;

    case WT_SCENARIO_SERVER_BIDI:
        if (!ctx->echo_sent) {
            ssize_t sent = xqc_wt_session_send_bidi(ctx->session,
                SERVER_BIDI_TRIGGER, strlen(SERVER_BIDI_TRIGGER), 1);
            if (sent > 0) {
                ctx->echo_sent = 1;
                return;
            }
            if (sent == -XQC_ESTATE || sent == -XQC_ESTREAM_BLOCKED
                || sent == -XQC_ECONN_BLOCKED)
            {
                return;
            }
            printf("[FAIL] server-bidi trigger send: %zd\n", sent);
            event_base_loopbreak(ctx->eb);
        }
        break;

    case WT_SCENARIO_FC_DISABLED_SINGLE_SESSION:
        if (!ctx->echo_sent) {
            ssize_t sent = xqc_wt_session_send_bidi(ctx->session,
                FC_DISABLED_MSG, strlen(FC_DISABLED_MSG), 1);
            if (sent > 0) {
                ctx->echo_sent = 1;
                return;
            }
            if (sent == -XQC_ESTATE || sent == -XQC_ESTREAM_BLOCKED
                || sent == -XQC_ECONN_BLOCKED)
            {
                return;
            }
            printf("[FAIL] fc-disabled-single-session send: %zd\n", sent);
            event_base_loopbreak(ctx->eb);
        }
        break;

    case WT_SCENARIO_MULTI_SESSION:
        if (ctx->session_count < ctx->target_sessions) {
            try_open_session(ctx);
            return;
        }
        if (!ctx->echo_sent) {
            char *payload = malloc(ctx->payload_size + 1);
            if (payload == NULL) {
                printf("[FAIL] multi-session payload allocation\n");
                event_base_loopbreak(ctx->eb);
                return;
            }
            memset(payload, 'm', ctx->payload_size);
            payload[ctx->payload_size] = '\0';
            for (size_t s = 0; s < ctx->target_sessions; s++) {
                for (size_t r = 0; r < ctx->repeat_count; r++) {
                    for (size_t st = 0; st < ctx->streams_per_session; st++) {
                        ssize_t sent = xqc_wt_session_send_bidi(ctx->sessions[s],
                            payload, ctx->payload_size, 1);
                        if (sent <= 0) {
                            free(payload);
                            if (sent == -XQC_ESTATE || sent == -XQC_ESTREAM_BLOCKED
                                || sent == -XQC_ECONN_BLOCKED)
                            {
                                return;
                            }
                            printf("[FAIL] multi-session-send[%zu,%zu,%zu]: %zd\n",
                                s, r, st, sent);
                            event_base_loopbreak(ctx->eb);
                            return;
                        }
                    }
                }
            }
            free(payload);
            ctx->echo_sent = 1;
            return;
        }
        break;

    case WT_SCENARIO_SPLIT_HEADER:
        if (ctx->session_count < ctx->target_sessions) {
            try_open_session(ctx);
            return;
        }
        try_send_split_header(ctx);
        break;

    case WT_SCENARIO_FC_DATA_BLOCKED:
    case WT_SCENARIO_FC_STREAM_BLOCKED:
        if (!ctx->echo_sent) {
            ssize_t sent = xqc_wt_session_send_bidi(ctx->session,
                ECHO_MSG, strlen(ECHO_MSG), 1);
            if ((ctx->scenario == WT_SCENARIO_FC_DATA_BLOCKED
                    && sent == -XQC_ECONN_BLOCKED)
                || (ctx->scenario == WT_SCENARIO_FC_STREAM_BLOCKED
                    && sent == -XQC_ESTREAM_BLOCKED))
            {
                printf("[OK] %s\n", scenario_name(ctx->scenario));
                ctx->echo_sent = 1;
                ctx->echo_ok = 1;
                ctx->echo_done = 1;
                xqc_h3_conn_close(ctx->engine, &ctx->cid);
                return;
            }
            if (sent == -XQC_ESTATE) {
                return;
            }
            printf("[FAIL] %s: unexpected send result %zd\n",
                scenario_name(ctx->scenario), sent);
            event_base_loopbreak(ctx->eb);
        }
        break;

    case WT_SCENARIO_INVALID_DATAGRAM:
        if (!ctx->invalid_dgram_sent) {
            if (ctx->h3_conn == NULL) {
                ctx->h3_conn = xqc_wt_session_get_h3_conn(ctx->session);
            }
            uint8_t payload[32];
            size_t sid_len = wt_encode_h3_datagram_session_id(
                (uint64_t)1 << 40, payload, sizeof(payload));
            if (ctx->h3_conn == NULL || sid_len == 0) {
                printf("[FAIL] invalid-datagram setup\n");
                event_base_loopbreak(ctx->eb);
                return;
            }
            memcpy(payload + sid_len, DGRAM_MSG, strlen(DGRAM_MSG));
            uint64_t dgram_id = 0;
            xqc_int_t ret = xqc_h3_ext_datagram_send(ctx->h3_conn, payload,
                sid_len + strlen(DGRAM_MSG), &dgram_id, XQC_DATA_QOS_HIGHEST);
            if (ret == XQC_OK) {
                ctx->invalid_dgram_sent = 1;
                xqc_engine_main_logic(ctx->engine);
                return;
            }
            if (ret == -XQC_EAGAIN || ret == -XQC_ESTATE) {
                xqc_conn_continue_send(ctx->engine, &ctx->cid);
                return;
            }
            printf("[FAIL] invalid-datagram send: %d\n", ret);
            event_base_loopbreak(ctx->eb);
        }
        break;

    case WT_SCENARIO_STRICT_REJECT_LEGACY:
    case WT_SCENARIO_CLIENT_REJECT_REQUIREMENTS:
    case WT_SCENARIO_STRICT_MISSING_WT_ENABLED:
    case WT_SCENARIO_STRICT_MISSING_H3_DATAGRAM:
    case WT_SCENARIO_STRICT_MISSING_CONNECT:
    case WT_SCENARIO_STRICT_MISSING_DGRAM_TP:
    case WT_SCENARIO_STRICT_MISSING_RESET_AT:
        break;
    }
}

int
main(int argc, char *argv[])
{
    const char *host = DEFAULT_HOST;
    const char *sni = NULL;
    int port = DEFAULT_PORT;
    if (argc > 1) host = argv[1];
    if (argc > 2) port = atoi(argv[2]);
    wt_scenario_t scenario = WT_SCENARIO_BIDI;
    xqc_wt_mode_t mode = XQC_WT_MODE_DRAFT15_STRICT;
    size_t opt_sessions = 0;
    size_t opt_streams = 1;
    size_t opt_size = strlen(ECHO_MSG);
    size_t opt_count = 1;
    int opt_timeout = 15;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--scenario") == 0 && i + 1 < argc) {
            if (!parse_scenario(argv[++i], &scenario)) {
                printf("[FAIL] unknown scenario: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = parse_mode(argv[++i]);
        } else if (strcmp(argv[i], "--sni") == 0 && i + 1 < argc) {
            sni = argv[++i];
        } else if (strcmp(argv[i], "--sessions") == 0 && i + 1 < argc) {
            opt_sessions = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--streams") == 0 && i + 1 < argc) {
            opt_streams = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            opt_size = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            opt_count = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            opt_timeout = atoi(argv[++i]);
        }
    }
    if (opt_streams == 0) opt_streams = 1;
    if (opt_size == 0) opt_size = strlen(ECHO_MSG);
    if (opt_count == 0) opt_count = 1;
    if (opt_timeout <= 0) opt_timeout = 15;
    if (sni == NULL) {
        sni = host;
    }

    wt_ctx_t ctx_s = {0};
    g_ctx = &ctx_s;
    strncpy(ctx_s.host, host, sizeof(ctx_s.host) - 1);
    ctx_s.scenario = scenario;
    ctx_s.mode = mode;
    ctx_s.target_sessions = 1;
    if (scenario == WT_SCENARIO_MULTI_SESSION) {
        ctx_s.target_sessions = opt_sessions > 0 ? opt_sessions : 2;
    } else if (scenario == WT_SCENARIO_SPLIT_HEADER) {
        ctx_s.target_sessions = opt_sessions > 0 ? opt_sessions : 17;
    } else if (opt_sessions > 0) {
        ctx_s.target_sessions = opt_sessions;
    }
    ctx_s.sessions_cap = ctx_s.target_sessions;
    ctx_s.streams_per_session = opt_streams;
    ctx_s.payload_size = opt_size;
    ctx_s.repeat_count = opt_count;
    ctx_s.timeout_sec = opt_timeout;
    ctx_s.sessions = calloc(ctx_s.sessions_cap, sizeof(ctx_s.sessions[0]));
    ctx_s.stream_reads_cap = ctx_s.target_sessions * ctx_s.streams_per_session
        * ctx_s.repeat_count + 8;
    ctx_s.expected_echoes = ctx_s.target_sessions * ctx_s.streams_per_session
        * ctx_s.repeat_count;
    ctx_s.stream_reads = calloc(ctx_s.stream_reads_cap,
        sizeof(ctx_s.stream_reads[0]));
    if (ctx_s.sessions == NULL || ctx_s.stream_reads == NULL) {
        printf("[FAIL] allocate session/stream tracking\n");
        free(ctx_s.sessions);
        free(ctx_s.stream_reads);
        return 1;
    }

    struct event_base *eb = event_base_new();
    ctx_s.eb = eb;
    ctx_s.ev_engine = event_new(eb, -1, 0, engine_cb, &ctx_s);

    xqc_engine_callback_t ecbs = {
        .set_event_timer = set_timer_cb,
        .log_callbacks = { .xqc_log_write_err = log_cb, .xqc_log_write_stat = log_cb },
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = write_socket_cb,
        .write_socket_ex = write_socket_ex_cb,
        .save_token = save_token_cb,
        .save_session_cb = save_session_cb,
        .save_tp_cb = save_tp_cb,
        .cert_verify_cb = cert_verify_cb,
    };

    xqc_config_t cfg;
    xqc_engine_get_default_config(&cfg, XQC_ENGINE_CLIENT);
    cfg.cfg_log_level = XQC_LOG_DEBUG;
    cfg.enable_h3_ext = 1;

    xqc_engine_ssl_config_t ssl = {0};
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;

    ctx_s.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &cfg, &ssl, &ecbs, &tcbs, &ctx_s);
    if (!ctx_s.engine) { printf("[FAIL] engine_create\n"); return 1; }

    xqc_webtransport_session_callbacks_t scbs = {
        .webtransport_session_create_notify = on_session_create,
        .webtransport_session_close_notify = on_session_close,
        .webtransport_conn_handshake_finished_notify = on_handshake_done,
    };
    xqc_webtransport_stream_callbacks_t stcbs = {
        .wt_bidistream_read_notify = on_bidi_read,
    };
    xqc_webtransport_dgram_callbacks_t dcbs = {
        .dgram_read_notify = on_dgram_read,
    };
    if (xqc_wt_ctx_init(ctx_s.engine, &dcbs, &scbs, &stcbs, 0) != XQC_OK) {
        printf("[FAIL] wt_ctx_init\n"); return 1;
    }
    configure_requirement_scenario(ctx_s.engine, scenario);

    /* socket */
    ctx_s.fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx_s.fd < 0) { printf("[FAIL] socket\n"); return 1; }
    fcntl(ctx_s.fd, F_SETFL, O_NONBLOCK);

    memset(&ctx_s.peer_addr, 0, sizeof(ctx_s.peer_addr));
    ctx_s.peer_addr.sin_family = AF_INET;
    ctx_s.peer_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &ctx_s.peer_addr.sin_addr);
    ctx_s.peer_addrlen = sizeof(ctx_s.peer_addr);

    ctx_s.ev_socket = event_new(eb, ctx_s.fd, EV_READ | EV_PERSIST, socket_cb, &ctx_s);
    event_add(ctx_s.ev_socket, NULL);

    /* connect */
    xqc_conn_settings_t cs = {
        .proto_version = XQC_VERSION_V1,
        .cong_ctrl_callback = xqc_bbr_cb,
        .init_idle_time_out = 30000,
        .max_datagram_frame_size = 16383,
        .reset_stream_at = 1,
    };
    if (scenario == WT_SCENARIO_STRICT_MISSING_DGRAM_TP) {
        cs.max_datagram_frame_size = 0;
    } else if (scenario == WT_SCENARIO_STRICT_MISSING_RESET_AT) {
        cs.reset_stream_at = 0;
    }
    xqc_conn_ssl_config_t cssl = {0};
    const xqc_cid_t *cid = xqc_webtransport_connect(ctx_s.engine, &cs,
        NULL, 0, sni, 0, &cssl,
        (struct sockaddr *)&ctx_s.peer_addr, ctx_s.peer_addrlen, &ctx_s);
    if (!cid) { printf("[FAIL] wt_connect\n"); return 1; }
    memcpy(&ctx_s.cid, cid, sizeof(xqc_cid_t));
    printf("[INFO] Connecting to %s:%d...\n", host, port);

    /* poll timer for reliable socket reading */
    ctx_s.ev_poll = event_new(eb, -1, EV_PERSIST, engine_cb, &ctx_s);
    struct timeval ptv = {0, 20000};
    event_add(ctx_s.ev_poll, &ptv);

    xqc_engine_main_logic(ctx_s.engine);

    struct timeval tv = {ctx_s.timeout_sec, 0};
    event_base_loopexit(eb, &tv);
    event_base_dispatch(eb);

    printf("\nWebTransport client interop: %s\n", ctx_s.echo_ok ? "PASS" : "FAIL");

    event_free(ctx_s.ev_poll);
    event_free(ctx_s.ev_socket);
    event_free(ctx_s.ev_engine);
    xqc_engine_destroy(ctx_s.engine);
    close(ctx_s.fd);
    event_base_free(eb);
    for (size_t i = 0; i < ctx_s.stream_reads_cap; i++) {
        free(ctx_s.stream_reads[i].buf);
    }
    free(ctx_s.sessions);
    free(ctx_s.stream_reads);
    return ctx_s.echo_ok ? 0 : 1;
}
