/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

/*
 * xqc_bench: a deterministic transfer benchmark.
 *
 * A client and a server engine run in one process and exchange datagrams
 * over a simulated link: a FIFO bottleneck of a fixed rate, a fixed one-way
 * delay, a tail-drop buffer and an optional random loss drawn from a seeded
 * generator. Time is virtual: both engines read the clock of the event loop,
 * which jumps from one event (a datagram arrival or an engine timer) to the
 * next. Given the same options, every run makes the same calls in the same
 * order, so the instructions it executes can be counted and compared, for
 * example with valgrind --tool=cachegrind. The library still draws its
 * connection IDs and the keys of its connection hash tables from
 * /dev/urandom: now and then a lookup meets another entry in its hash bucket,
 * which adds a few instructions to a run.
 *
 * The client fetches <requests> responses of <bytes> bytes each, over HTTP/3
 * (ALPN h3) or over HTTP/0.9 on raw QUIC streams (ALPN hq-interop), then
 * closes the connection. The output is one line of counters that depend on
 * the options only.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_http3.h>


#define XQC_BENCH_ALPN_HQ       "hq-interop"
#define XQC_BENCH_DGRAM_MAX     2048
#define XQC_BENCH_NEVER         UINT64_MAX
#define XQC_BENCH_START_US      UINT64_C(1000000000000)
#define XQC_BENCH_PATTERN_LEN   65536
#define XQC_BENCH_CHUNK         16384
#define XQC_BENCH_REQ_MAX       64


typedef struct xqc_bench_s xqc_bench_t;


typedef struct xqc_bench_dgram_s {
    struct xqc_bench_dgram_s   *next;
    xqc_usec_t                  arrive;
    size_t                      len;
    unsigned char               buf[XQC_BENCH_DGRAM_MAX];
} xqc_bench_dgram_t;


/* one direction of the simulated link */
typedef struct xqc_bench_link_s {
    xqc_bench_dgram_t          *head;
    xqc_bench_dgram_t          *tail;
    xqc_usec_t                  busy_until;
    uint64_t                    rng;
    uint64_t                    sent;
    uint64_t                    sent_bytes;
    uint64_t                    lost;
    uint64_t                    overflow;
} xqc_bench_link_t;


typedef struct xqc_bench_endpoint_s {
    xqc_bench_t                *bench;
    xqc_engine_t               *engine;
    struct sockaddr_in          addr;
    xqc_bench_link_t           *out;
    xqc_usec_t                  timer;
    int                         closed;
} xqc_bench_endpoint_t;


typedef struct xqc_bench_stream_s {
    xqc_bench_t                *bench;
    xqc_h3_request_t           *h3_request;
    xqc_stream_t               *stream;
    char                        req[64];
    size_t                      req_len;
    size_t                      req_recvd;
    char                        line[80];
    size_t                      line_len;
    size_t                      line_sent;
    uint64_t                    body_len;
    uint64_t                    body_sent;
    uint64_t                    body_recvd;
    int                         is_client;
    int                         header_sent;
    int                         fin_sent;
    int                         fin_recvd;
} xqc_bench_stream_t;


struct xqc_bench_s {
    /* options */
    int                         hq;
    uint64_t                    bytes;
    unsigned                    requests;
    uint64_t                    rate_bps;
    xqc_usec_t                  delay_us;
    xqc_usec_t                  queue_us;
    uint32_t                    loss_ppm;
    uint64_t                    seed;
    const char                 *cc;
    const char                 *key_file;
    const char                 *cert_file;
    int                         verbose;
    FILE                       *log_file;

    /* state */
    xqc_usec_t                  now;
    xqc_bench_link_t            c2s;
    xqc_bench_link_t            s2c;
    xqc_bench_endpoint_t        cli;
    xqc_bench_endpoint_t        srv;
    xqc_bench_dgram_t          *free_dgrams;
    xqc_cid_t                   cid;
    unsigned                    done_requests;
    xqc_usec_t                  xfer_done;
    int                         close_sent;
    int                         failed;
    uint64_t                    errors_logged;
    xqc_bench_stream_t          cli_streams[XQC_BENCH_REQ_MAX];
    unsigned char               pattern[XQC_BENCH_PATTERN_LEN];
    unsigned char               recv_buf[XQC_BENCH_CHUNK];
};


static xqc_bench_t g_bench;


static xqc_usec_t xqc_bench_clock(void);
static uint64_t xqc_bench_random(xqc_bench_link_t *link);
static xqc_bench_dgram_t *xqc_bench_dgram_get(xqc_bench_t *b);
static void xqc_bench_link_send(xqc_bench_t *b, xqc_bench_link_t *link,
    const unsigned char *buf, size_t size);
static int xqc_bench_link_deliver(xqc_bench_t *b, xqc_bench_link_t *link,
    xqc_bench_endpoint_t *from, xqc_bench_endpoint_t *to);
static void xqc_bench_set_event_timer(xqc_usec_t wake_after,
    void *engine_user_data);
static void xqc_bench_log_write(xqc_log_level_t lvl, const void *buf,
    size_t size, void *engine_user_data);
static ssize_t xqc_bench_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data);
static int xqc_bench_server_accept(xqc_engine_t *engine,
    xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data);
static void xqc_bench_save_token(const unsigned char *token,
    unsigned token_len, void *user_data);
static void xqc_bench_save_string(const char *data, size_t data_len,
    void *user_data);
static void xqc_bench_body_check(xqc_bench_t *b, xqc_bench_stream_t *s,
    const unsigned char *data, size_t len);
static void xqc_bench_request_done(xqc_bench_t *b);
static int xqc_bench_parse_request(xqc_bench_stream_t *s, const char *path,
    size_t path_len);
static int xqc_bench_h3_conn_create(xqc_h3_conn_t *h3c, const xqc_cid_t *cid,
    void *user_data);
static int xqc_bench_h3_conn_close(xqc_h3_conn_t *h3c, const xqc_cid_t *cid,
    void *user_data);
static void xqc_bench_h3_handshake_finished(xqc_h3_conn_t *h3c,
    void *user_data);
static int xqc_bench_h3_request_create(xqc_h3_request_t *req,
    void *user_data);
static int xqc_bench_h3_request_close(xqc_h3_request_t *req,
    void *user_data);
static int xqc_bench_h3_send(xqc_bench_stream_t *s);
static int xqc_bench_h3_request_write(xqc_h3_request_t *req,
    void *user_data);
static int xqc_bench_h3_request_read(xqc_h3_request_t *req,
    xqc_request_notify_flag_t flag, void *user_data);
static int xqc_bench_hq_conn_create(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data, void *proto_data);
static int xqc_bench_hq_conn_close(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data, void *proto_data);
static void xqc_bench_hq_handshake_finished(xqc_connection_t *conn,
    void *user_data, void *proto_data);
static int xqc_bench_hq_stream_create(xqc_stream_t *stream, void *user_data);
static int xqc_bench_hq_stream_close(xqc_stream_t *stream, void *user_data);
static int xqc_bench_hq_send(xqc_bench_stream_t *s);
static int xqc_bench_hq_send_request(xqc_bench_stream_t *s);
static int xqc_bench_hq_stream_write(xqc_stream_t *stream, void *user_data);
static int xqc_bench_hq_stream_read(xqc_stream_t *stream, void *user_data);
static int xqc_bench_engine_create(xqc_bench_t *b, xqc_bench_endpoint_t *ep,
    xqc_engine_type_t type);
static int xqc_bench_connect(xqc_bench_t *b);
static void xqc_bench_close(xqc_bench_t *b);
static int xqc_bench_run(xqc_bench_t *b);
static void xqc_bench_usage(const char *prog);
static int xqc_bench_parse_uint(const char *s, uint64_t *out);


static xqc_usec_t
xqc_bench_clock(void)
{
    return g_bench.now;
}


/*
 * xorshift64*, one sequence per direction: the datagrams that a direction
 * loses depend on how many it carried before, not on the other direction.
 */
static uint64_t
xqc_bench_random(xqc_bench_link_t *link)
{
    link->rng ^= link->rng >> 12;
    link->rng ^= link->rng << 25;
    link->rng ^= link->rng >> 27;
    return link->rng * 0x2545F4914F6CDD1DULL;
}


static xqc_bench_dgram_t *
xqc_bench_dgram_get(xqc_bench_t *b)
{
    xqc_bench_dgram_t *d = b->free_dgrams;

    if (d != NULL) {
        b->free_dgrams = d->next;
        return d;
    }

    d = malloc(sizeof(*d));
    if (d == NULL) {
        fprintf(stderr, "xqc_bench: out of memory\n");
        exit(1);
    }
    return d;
}


static void
xqc_bench_link_send(xqc_bench_t *b, xqc_bench_link_t *link,
    const unsigned char *buf, size_t size)
{
    xqc_bench_dgram_t *d;
    xqc_usec_t         start, done;

    link->sent++;
    link->sent_bytes += size;

    if (b->loss_ppm > 0
        && xqc_bench_random(link) % 1000000 < b->loss_ppm)
    {
        link->lost++;
        return;
    }

    /* the bottleneck serializes datagrams; the buffer holds queue_us */
    start = link->busy_until > b->now ? link->busy_until : b->now;
    if (start - b->now > b->queue_us) {
        link->overflow++;
        return;
    }

    done = start + ((uint64_t) size * 8 * 1000000 + b->rate_bps - 1)
                   / b->rate_bps;
    link->busy_until = done;

    d = xqc_bench_dgram_get(b);
    d->next = NULL;
    d->arrive = done + b->delay_us;
    d->len = size;
    memcpy(d->buf, buf, size);

    if (link->tail != NULL) {
        link->tail->next = d;

    } else {
        link->head = d;
    }
    link->tail = d;
}


/* deliver the datagrams that have arrived; returns how many */
static int
xqc_bench_link_deliver(xqc_bench_t *b, xqc_bench_link_t *link,
    xqc_bench_endpoint_t *from, xqc_bench_endpoint_t *to)
{
    xqc_bench_dgram_t *d;
    int                n = 0;

    while ((d = link->head) != NULL && d->arrive <= b->now) {
        link->head = d->next;
        if (link->head == NULL) {
            link->tail = NULL;
        }

        if (xqc_engine_packet_process(to->engine, d->buf, d->len,
                                      (struct sockaddr *) &to->addr,
                                      sizeof(to->addr),
                                      (struct sockaddr *) &from->addr,
                                      sizeof(from->addr),
                                      b->now, to) != XQC_OK
            && b->verbose)
        {
            fprintf(stderr, "xqc_bench: packet_process failed\n");
        }

        d->next = b->free_dgrams;
        b->free_dgrams = d;
        n++;
    }

    if (n > 0) {
        xqc_engine_finish_recv(to->engine);
    }
    return n;
}


static void
xqc_bench_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
    xqc_bench_endpoint_t *ep = engine_user_data;

    ep->timer = ep->bench->now + wake_after;
}


static void
xqc_bench_log_write(xqc_log_level_t lvl, const void *buf, size_t size,
    void *engine_user_data)
{
    xqc_bench_endpoint_t *ep = engine_user_data;
    xqc_bench_t          *b = ep->bench;

    if (lvl == XQC_LOG_FATAL || lvl == XQC_LOG_ERROR) {
        b->errors_logged++;
        if (b->verbose) {
            fprintf(stderr, "%.*s\n", (int) size, (const char *) buf);
        }
    }

    if (b->log_file != NULL) {
        fprintf(b->log_file, "%" PRIu64 " %c %.*s\n",
                b->now - XQC_BENCH_START_US, ep == &b->cli ? 'C' : 'S',
                (int) size, (const char *) buf);
    }
}


static ssize_t
xqc_bench_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data)
{
    xqc_bench_endpoint_t *ep = conn_user_data;

    if (size > XQC_BENCH_DGRAM_MAX) {
        return XQC_SOCKET_ERROR;
    }

    xqc_bench_link_send(ep->bench, ep->out, buf, size);
    return size;
}


static int
xqc_bench_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data)
{
    return 0;
}


static void
xqc_bench_save_token(const unsigned char *token, unsigned token_len,
    void *user_data)
{
}


static void
xqc_bench_save_string(const char *data, size_t data_len, void *user_data)
{
}


/* the server sends the pattern repeated; check what the client receives */
static void
xqc_bench_body_check(xqc_bench_t *b, xqc_bench_stream_t *s,
    const unsigned char *data, size_t len)
{
    while (len > 0) {
        size_t off = s->body_recvd % XQC_BENCH_PATTERN_LEN;
        size_t n = XQC_BENCH_PATTERN_LEN - off;

        if (n > len) {
            n = len;
        }
        if (memcmp(data, b->pattern + off, n) != 0) {
            fprintf(stderr, "xqc_bench: corrupt body at offset %" PRIu64
                    "\n", s->body_recvd);
            b->failed = 1;
        }
        s->body_recvd += n;
        data += n;
        len -= n;
    }
}


static void
xqc_bench_request_done(xqc_bench_t *b)
{
    b->done_requests++;
    if (b->done_requests == b->requests && !b->close_sent) {
        b->xfer_done = b->now;
        b->close_sent = 1;
        if (b->hq) {
            xqc_conn_close(b->cli.engine, &b->cid);

        } else {
            xqc_h3_conn_close(b->cli.engine, &b->cid);
        }
    }
}


/* the request path is "/<decimal response length>" */
static int
xqc_bench_parse_request(xqc_bench_stream_t *s, const char *path,
    size_t path_len)
{
    uint64_t len = 0;
    size_t   i;

    if (path_len < 2 || path[0] != '/') {
        return -1;
    }
    for (i = 1; i < path_len; i++) {
        if (path[i] < '0' || path[i] > '9' || len > UINT64_MAX / 10 - 9) {
            return -1;
        }
        len = len * 10 + (uint64_t) (path[i] - '0');
    }
    s->body_len = len;
    return 0;
}


/* HTTP/3 */

static int
xqc_bench_h3_conn_create(xqc_h3_conn_t *h3c, const xqc_cid_t *cid,
    void *user_data)
{
    return 0;
}


static int
xqc_bench_h3_conn_close(xqc_h3_conn_t *h3c, const xqc_cid_t *cid,
    void *user_data)
{
    xqc_bench_t *b = &g_bench;

    if (user_data == &b->cli) {
        b->cli.closed = 1;

    } else {
        b->srv.closed = 1;
    }
    return 0;
}


static void
xqc_bench_h3_handshake_finished(xqc_h3_conn_t *h3c, void *user_data)
{
}


static int
xqc_bench_h3_request_create(xqc_h3_request_t *req, void *user_data)
{
    xqc_bench_stream_t *s;

    /* requests that the client creates come with their context */
    if (user_data != NULL) {
        return 0;
    }

    s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return -1;
    }
    s->bench = &g_bench;
    s->h3_request = req;
    xqc_h3_request_set_user_data(req, s);
    return 0;
}


static int
xqc_bench_h3_request_close(xqc_h3_request_t *req, void *user_data)
{
    xqc_bench_stream_t *s = user_data;

    /* client streams live in the bench; server streams are allocated */
    if (s != NULL && (s < s->bench->cli_streams
                      || s >= s->bench->cli_streams + XQC_BENCH_REQ_MAX))
    {
        free(s);
    }
    return 0;
}


/* server: send the response headers, then as much body as accepted */
static int
xqc_bench_h3_send(xqc_bench_stream_t *s)
{
    xqc_bench_t *b = s->bench;
    ssize_t      ret;

    if (!s->header_sent) {
        char                len_str[24];
        xqc_http_header_t   hdr[2];
        xqc_http_headers_t  headers;

        snprintf(len_str, sizeof(len_str), "%" PRIu64, s->body_len);
        memset(hdr, 0, sizeof(hdr));
        hdr[0].name.iov_base = ":status";
        hdr[0].name.iov_len = 7;
        hdr[0].value.iov_base = "200";
        hdr[0].value.iov_len = 3;
        hdr[1].name.iov_base = "content-length";
        hdr[1].name.iov_len = 14;
        hdr[1].value.iov_base = len_str;
        hdr[1].value.iov_len = strlen(len_str);
        headers.headers = hdr;
        headers.count = 2;
        headers.capacity = 2;
        headers.total_len = 0;

        ret = xqc_h3_request_send_headers(s->h3_request, &headers,
                                          s->body_len == 0);
        if (ret == -XQC_EAGAIN) {
            return 0;
        }
        if (ret < 0) {
            return -1;
        }
        s->header_sent = 1;
        s->fin_sent = s->body_len == 0;
    }

    while (!s->fin_sent) {
        uint64_t off = s->body_sent % XQC_BENCH_PATTERN_LEN;
        uint64_t n = XQC_BENCH_PATTERN_LEN - off;
        uint8_t  fin;

        if (n > s->body_len - s->body_sent) {
            n = s->body_len - s->body_sent;
        }
        fin = s->body_sent + n == s->body_len;

        ret = xqc_h3_request_send_body(s->h3_request, b->pattern + off, n,
                                       fin);
        if (ret == -XQC_EAGAIN) {
            return 0;
        }
        if (ret < 0) {
            return -1;
        }
        s->body_sent += ret;
        if (fin && (uint64_t) ret == n) {
            s->fin_sent = 1;
        }
    }
    return 0;
}


static int
xqc_bench_h3_request_write(xqc_h3_request_t *req, void *user_data)
{
    xqc_bench_stream_t *s = user_data;

    /* client requests are sent whole at creation */
    if (s == NULL || s->is_client || s->req_len == 0 || s->fin_sent) {
        return 0;
    }
    return xqc_bench_h3_send(s);
}


static int
xqc_bench_h3_request_read(xqc_h3_request_t *req,
    xqc_request_notify_flag_t flag, void *user_data)
{
    xqc_bench_stream_t *s = user_data;
    xqc_bench_t        *b = s->bench;
    uint8_t             fin = 0;
    ssize_t             n;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(req, &fin);
        size_t              i;

        if (headers == NULL) {
            return -1;
        }

        /* the server answers the :path of the request */
        if (!s->is_client && s->req_len == 0) {
            for (i = 0; i < headers->count; i++) {
                xqc_http_header_t *h = &headers->headers[i];

                if (h->name.iov_len == 5
                    && memcmp(h->name.iov_base, ":path", 5) == 0
                    && xqc_bench_parse_request(s, h->value.iov_base,
                                               h->value.iov_len) == 0)
                {
                    s->req_len = h->value.iov_len;
                }
            }
            if (s->req_len == 0) {
                return -1;
            }
            return xqc_bench_h3_send(s);
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        do {
            n = xqc_h3_request_recv_body(req, b->recv_buf,
                                         sizeof(b->recv_buf), &fin);
            if (n == -XQC_EAGAIN) {
                break;
            }
            if (n < 0) {
                return -1;
            }
            xqc_bench_body_check(b, s, b->recv_buf, n);
        } while (!fin && n > 0);
    }

    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;
    }

    if (fin && !s->fin_recvd && s->is_client) {
        s->fin_recvd = 1;
        if (s->body_recvd != s->body_len) {
            fprintf(stderr, "xqc_bench: got %" PRIu64 " of %" PRIu64
                    " bytes\n", s->body_recvd, s->body_len);
            b->failed = 1;
        }
        xqc_bench_request_done(b);
    }
    return 0;
}


/* HTTP/0.9 on QUIC streams (hq-interop) */

static int
xqc_bench_hq_conn_create(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *proto_data)
{
    return 0;
}


static int
xqc_bench_hq_conn_close(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *proto_data)
{
    xqc_bench_endpoint_t *ep = user_data;

    ep->closed = 1;
    return 0;
}


static void
xqc_bench_hq_handshake_finished(xqc_connection_t *conn, void *user_data,
    void *proto_data)
{
}


static int
xqc_bench_hq_stream_create(xqc_stream_t *stream, void *user_data)
{
    xqc_bench_stream_t *s;

    if (user_data != NULL) {
        return 0;
    }

    s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return -1;
    }
    s->bench = &g_bench;
    s->stream = stream;
    xqc_stream_set_user_data(stream, s);
    return 0;
}


static int
xqc_bench_hq_stream_close(xqc_stream_t *stream, void *user_data)
{
    return xqc_bench_h3_request_close(NULL, user_data);
}


static int
xqc_bench_hq_send(xqc_bench_stream_t *s)
{
    xqc_bench_t *b = s->bench;
    ssize_t      ret;

    while (!s->fin_sent) {
        uint64_t off = s->body_sent % XQC_BENCH_PATTERN_LEN;
        uint64_t n = XQC_BENCH_PATTERN_LEN - off;
        uint8_t  fin;

        if (n > s->body_len - s->body_sent) {
            n = s->body_len - s->body_sent;
        }
        fin = s->body_sent + n == s->body_len;

        ret = xqc_stream_send(s->stream, b->pattern + off, n, fin);
        if (ret == -XQC_EAGAIN) {
            return 0;
        }
        if (ret < 0) {
            return -1;
        }
        s->body_sent += ret;
        if (fin && (uint64_t) ret == n) {
            s->fin_sent = 1;
        }
    }
    return 0;
}


/* client: "GET /<length>\r\n" and the end of the stream */
static int
xqc_bench_hq_send_request(xqc_bench_stream_t *s)
{
    ssize_t ret;

    while (!s->fin_sent) {
        ret = xqc_stream_send(s->stream,
                              (unsigned char *) s->line + s->line_sent,
                              s->line_len - s->line_sent, 1);
        if (ret == -XQC_EAGAIN) {
            return 0;
        }
        if (ret < 0) {
            return -1;
        }
        s->line_sent += ret;
        s->fin_sent = s->line_sent == s->line_len;
    }
    return 0;
}


static int
xqc_bench_hq_stream_write(xqc_stream_t *stream, void *user_data)
{
    xqc_bench_stream_t *s = user_data;

    if (s == NULL || s->fin_sent) {
        return 0;
    }
    if (s->is_client) {
        return xqc_bench_hq_send_request(s);
    }
    if (s->req_len == 0) {
        return 0;
    }
    return xqc_bench_hq_send(s);
}


static int
xqc_bench_hq_stream_read(xqc_stream_t *stream, void *user_data)
{
    xqc_bench_stream_t *s = user_data;
    xqc_bench_t        *b = s->bench;
    uint8_t             fin = 0;
    ssize_t             n;

    if (s->is_client) {
        /* client: the response body */
        do {
            n = xqc_stream_recv(stream, b->recv_buf, sizeof(b->recv_buf),
                                &fin);
            if (n == -XQC_EAGAIN) {
                break;
            }
            if (n < 0) {
                return -1;
            }
            xqc_bench_body_check(b, s, b->recv_buf, n);
        } while (!fin && n > 0);

        if (fin && !s->fin_recvd) {
            s->fin_recvd = 1;
            if (s->body_recvd != s->body_len) {
                fprintf(stderr, "xqc_bench: got %" PRIu64 " of %" PRIu64
                        " bytes\n", s->body_recvd, s->body_len);
                b->failed = 1;
            }
            xqc_bench_request_done(b);
        }
        return 0;
    }

    /* server: "GET /<length>\r\n", then the end of the stream */
    do {
        unsigned char buf[64];

        n = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
        if (n == -XQC_EAGAIN) {
            break;
        }
        if (n < 0 || s->req_recvd + n > sizeof(s->req)) {
            return -1;
        }
        memcpy(s->req + s->req_recvd, buf, n);
        s->req_recvd += n;
    } while (!fin && n > 0);

    if (fin && s->req_len == 0) {
        size_t len = s->req_recvd;

        while (len > 0 && (s->req[len - 1] == '\n'
                           || s->req[len - 1] == '\r'))
        {
            len--;
        }
        if (len < 5 || memcmp(s->req, "GET ", 4) != 0
            || xqc_bench_parse_request(s, s->req + 4, len - 4) != 0)
        {
            return -1;
        }
        s->req_len = len;
        return xqc_bench_hq_send(s);
    }
    return 0;
}


static int
xqc_bench_engine_create(xqc_bench_t *b, xqc_bench_endpoint_t *ep,
    xqc_engine_type_t type)
{
    xqc_config_t               config;
    xqc_engine_ssl_config_t    ssl_config;
    xqc_engine_callback_t      callbacks;
    xqc_transport_callbacks_t  tcbs;
    xqc_conn_settings_t        settings;

    if (xqc_engine_get_default_config(&config, type) != XQC_OK) {
        return -1;
    }
    config.cfg_log_level = b->log_file != NULL ? XQC_LOG_DEBUG : XQC_LOG_ERROR;
    config.cfg_log_event = 0;

    memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.ciphers = XQC_TLS_CIPHERS;
    ssl_config.groups = XQC_TLS_GROUPS;
    if (type == XQC_ENGINE_SERVER) {
        ssl_config.private_key_file = (char *) b->key_file;
        ssl_config.cert_file = (char *) b->cert_file;
    }

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.set_event_timer = xqc_bench_set_event_timer;
    callbacks.log_callbacks.xqc_log_write_err = xqc_bench_log_write;
    callbacks.log_callbacks.xqc_log_write_stat = xqc_bench_log_write;
    callbacks.realtime_ts = xqc_bench_clock;
    callbacks.monotonic_ts = xqc_bench_clock;

    memset(&tcbs, 0, sizeof(tcbs));
    tcbs.write_socket = xqc_bench_write_socket;
    tcbs.save_token = xqc_bench_save_token;
    tcbs.save_session_cb = xqc_bench_save_string;
    tcbs.save_tp_cb = xqc_bench_save_string;
    if (type == XQC_ENGINE_SERVER) {
        tcbs.server_accept = xqc_bench_server_accept;
    }

    ep->bench = b;
    ep->engine = xqc_engine_create(type, &config, &ssl_config, &callbacks,
                                   &tcbs, ep);
    if (ep->engine == NULL) {
        return -1;
    }

    if (b->hq) {
        xqc_app_proto_callbacks_t ap_cbs;

        memset(&ap_cbs, 0, sizeof(ap_cbs));
        ap_cbs.conn_cbs.conn_create_notify = xqc_bench_hq_conn_create;
        ap_cbs.conn_cbs.conn_close_notify = xqc_bench_hq_conn_close;
        ap_cbs.conn_cbs.conn_handshake_finished =
            xqc_bench_hq_handshake_finished;
        ap_cbs.stream_cbs.stream_create_notify = xqc_bench_hq_stream_create;
        ap_cbs.stream_cbs.stream_close_notify = xqc_bench_hq_stream_close;
        ap_cbs.stream_cbs.stream_read_notify = xqc_bench_hq_stream_read;
        ap_cbs.stream_cbs.stream_write_notify = xqc_bench_hq_stream_write;
        if (xqc_engine_register_alpn(ep->engine, XQC_BENCH_ALPN_HQ,
                                     strlen(XQC_BENCH_ALPN_HQ), &ap_cbs,
                                     NULL) != XQC_OK)
        {
            return -1;
        }

    } else {
        xqc_h3_callbacks_t h3_cbs;

        memset(&h3_cbs, 0, sizeof(h3_cbs));
        h3_cbs.h3c_cbs.h3_conn_create_notify = xqc_bench_h3_conn_create;
        h3_cbs.h3c_cbs.h3_conn_close_notify = xqc_bench_h3_conn_close;
        h3_cbs.h3c_cbs.h3_conn_handshake_finished =
            xqc_bench_h3_handshake_finished;
        h3_cbs.h3r_cbs.h3_request_create_notify = xqc_bench_h3_request_create;
        h3_cbs.h3r_cbs.h3_request_close_notify = xqc_bench_h3_request_close;
        h3_cbs.h3r_cbs.h3_request_read_notify = xqc_bench_h3_request_read;
        h3_cbs.h3r_cbs.h3_request_write_notify = xqc_bench_h3_request_write;
        if (xqc_h3_ctx_init(ep->engine, &h3_cbs) != XQC_OK) {
            return -1;
        }
    }

    if (type == XQC_ENGINE_SERVER) {
        settings = xqc_conn_get_conn_settings_template(
            XQC_CONN_SETTINGS_DEFAULT);
        if (strcmp(b->cc, "bbr") == 0) {
            settings.cong_ctrl_callback = xqc_bbr_cb;
            settings.pacing_on = 1;
        }
        xqc_server_set_conn_settings(ep->engine, &settings);
    }
    return 0;
}


static int
xqc_bench_connect(xqc_bench_t *b)
{
    xqc_conn_settings_t    settings;
    xqc_conn_ssl_config_t  ssl;
    const xqc_cid_t       *cid;
    unsigned               i;

    settings = xqc_conn_get_conn_settings_template(XQC_CONN_SETTINGS_DEFAULT);
    if (strcmp(b->cc, "bbr") == 0) {
        settings.cong_ctrl_callback = xqc_bbr_cb;
        settings.pacing_on = 1;
    }

    memset(&ssl, 0, sizeof(ssl));
    ssl.cert_verify_flag = 0;

    if (b->hq) {
        cid = xqc_connect(b->cli.engine, &settings, NULL, 0, "bench.xquic",
                          0, &ssl, (struct sockaddr *) &b->srv.addr,
                          sizeof(b->srv.addr), XQC_BENCH_ALPN_HQ, &b->cli);

    } else {
        cid = xqc_h3_connect(b->cli.engine, &settings, NULL, 0, "bench.xquic",
                             0, &ssl, (struct sockaddr *) &b->srv.addr,
                             sizeof(b->srv.addr), &b->cli);
    }
    if (cid == NULL) {
        return -1;
    }
    memcpy(&b->cid, cid, sizeof(*cid));

    for (i = 0; i < b->requests; i++) {
        xqc_bench_stream_t *s = &b->cli_streams[i];
        int                 len;

        s->bench = b;
        s->is_client = 1;
        s->body_len = b->bytes;
        len = snprintf(s->req, sizeof(s->req), "/%" PRIu64, b->bytes);
        s->req_len = len;

        if (b->hq) {
            s->line_len = snprintf(s->line, sizeof(s->line),
                                   "GET /%" PRIu64 "\r\n", b->bytes);
            s->stream = xqc_stream_create(b->cli.engine, &b->cid, NULL, s);
            if (s->stream == NULL || xqc_bench_hq_send_request(s) != 0) {
                return -1;
            }

        } else {
            xqc_http_header_t  hdr[6];
            xqc_http_headers_t headers;
            const char        *names[6] = {":method", ":scheme",
                ":authority", ":path", "user-agent", "accept"};
            const char        *values[6] = {"GET", "https", "bench.xquic",
                s->req, "xqc_bench", "*/*"};
            int                j;

            memset(hdr, 0, sizeof(hdr));
            for (j = 0; j < 6; j++) {
                hdr[j].name.iov_base = (void *) names[j];
                hdr[j].name.iov_len = strlen(names[j]);
                hdr[j].value.iov_base = (void *) values[j];
                hdr[j].value.iov_len = strlen(values[j]);
            }
            headers.headers = hdr;
            headers.count = 6;
            headers.capacity = 6;
            headers.total_len = 0;

            s->h3_request = xqc_h3_request_create(b->cli.engine, &b->cid,
                                                  NULL, s);
            if (s->h3_request == NULL
                || xqc_h3_request_send_headers(s->h3_request, &headers, 1)
                   < 0)
            {
                return -1;
            }
        }
    }
    return 0;
}


static void
xqc_bench_close(xqc_bench_t *b)
{
    xqc_bench_dgram_t *d;
    xqc_bench_link_t  *links[2] = {&b->c2s, &b->s2c};
    int                i;

    if (b->cli.engine != NULL) {
        xqc_engine_destroy(b->cli.engine);
        b->cli.engine = NULL;
    }
    if (b->srv.engine != NULL) {
        xqc_engine_destroy(b->srv.engine);
        b->srv.engine = NULL;
    }

    for (i = 0; i < 2; i++) {
        while ((d = links[i]->head) != NULL) {
            links[i]->head = d->next;
            free(d);
        }
        links[i]->tail = NULL;
    }
    while ((d = b->free_dgrams) != NULL) {
        b->free_dgrams = d->next;
        free(d);
    }
}


static int
xqc_bench_run(xqc_bench_t *b)
{
    /*
     * A stalled transfer ends after one virtual hour, and a loop that stops
     * the clock after a million events at one time.
     */
    xqc_usec_t deadline = b->now + UINT64_C(3600000000);
    xqc_usec_t last = 0;
    uint64_t   same = 0;

    while (!(b->cli.closed && b->srv.closed)) {
        xqc_usec_t next = XQC_BENCH_NEVER;

        if (b->now == last) {
            if (++same > 1000000) {
                fprintf(stderr, "xqc_bench: the clock stopped\n");
                return -1;
            }

        } else {
            last = b->now;
            same = 0;
        }

        if (b->cli.timer != 0 && b->cli.timer < next) {
            next = b->cli.timer;
        }
        if (b->srv.timer != 0 && b->srv.timer < next) {
            next = b->srv.timer;
        }
        if (b->c2s.head != NULL && b->c2s.head->arrive < next) {
            next = b->c2s.head->arrive;
        }
        if (b->s2c.head != NULL && b->s2c.head->arrive < next) {
            next = b->s2c.head->arrive;
        }
        if (next == XQC_BENCH_NEVER) {
            fprintf(stderr, "xqc_bench: no event left before the end\n");
            return -1;
        }
        if (next > deadline) {
            fprintf(stderr, "xqc_bench: no progress before the deadline\n");
            return -1;
        }
        if (next > b->now) {
            b->now = next;
        }

        xqc_bench_link_deliver(b, &b->c2s, &b->cli, &b->srv);
        xqc_bench_link_deliver(b, &b->s2c, &b->srv, &b->cli);

        if (b->cli.timer != 0 && b->cli.timer <= b->now) {
            b->cli.timer = 0;
            xqc_engine_main_logic(b->cli.engine);
        }
        if (b->srv.timer != 0 && b->srv.timer <= b->now) {
            b->srv.timer = 0;
            xqc_engine_main_logic(b->srv.engine);
        }
    }
    return 0;
}


static void
xqc_bench_usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  -p h3|hq     application protocol (default h3)\n"
        "  -s <bytes>   response size of each request (default 8388608)\n"
        "  -n <count>   requests, sent at once (default 1, at most %d)\n"
        "  -r <kbit/s>  bottleneck rate (default 100000)\n"
        "  -d <us>      one-way delay (default 10000)\n"
        "  -q <us>      queueing delay the buffer holds (default 1000000)\n"
        "  -l <ppm>     random loss, per million datagrams (default 0)\n"
        "  -S <seed>    seed of the loss pattern (default 1)\n"
        "  -c cubic|bbr congestion control (default cubic)\n"
        "  -k <file>    server private key (default server.key)\n"
        "  -K <file>    server certificate (default server.crt)\n"
        "  -v           print xquic error logs\n"
        "  -L <file>    write the debug logs of both engines to <file>\n",
        prog, XQC_BENCH_REQ_MAX);
}


static int
xqc_bench_parse_uint(const char *s, uint64_t *out)
{
    char *end;

    errno = 0;
    *out = strtoull(s, &end, 10);
    return (errno != 0 || end == s || *end != '\0' || s[0] == '-') ? -1 : 0;
}


int
main(int argc, char *argv[])
{
    xqc_bench_t *b = &g_bench;
    uint64_t     v;
    size_t       i;
    int          ch, ret;

    b->bytes = 8 * 1024 * 1024;
    b->requests = 1;
    b->rate_bps = 100000000;
    b->delay_us = 10000;
    b->queue_us = 1000000;
    b->seed = 1;
    b->cc = "cubic";
    b->key_file = "server.key";
    b->cert_file = "server.crt";

    while ((ch = getopt(argc, argv, "p:s:n:r:d:q:l:S:c:k:K:vL:")) != -1) {
        switch (ch) {
        case 'p':
            if (strcmp(optarg, "h3") != 0 && strcmp(optarg, "hq") != 0) {
                xqc_bench_usage(argv[0]);
                return 2;
            }
            b->hq = strcmp(optarg, "hq") == 0;
            break;
        case 'c':
            if (strcmp(optarg, "cubic") != 0 && strcmp(optarg, "bbr") != 0) {
                xqc_bench_usage(argv[0]);
                return 2;
            }
            b->cc = optarg;
            break;
        case 'k':
            b->key_file = optarg;
            break;
        case 'K':
            b->cert_file = optarg;
            break;
        case 'v':
            b->verbose = 1;
            break;
        case 'L':
            b->log_file = fopen(optarg, "w");
            if (b->log_file == NULL) {
                fprintf(stderr, "xqc_bench: cannot open %s\n", optarg);
                return 2;
            }
            break;
        case 's': case 'n': case 'r': case 'd': case 'q': case 'l': case 'S':
            if (xqc_bench_parse_uint(optarg, &v) != 0) {
                xqc_bench_usage(argv[0]);
                return 2;
            }
            if (ch == 's') {
                b->bytes = v;
            } else if (ch == 'n') {
                if (v == 0 || v > XQC_BENCH_REQ_MAX) {
                    xqc_bench_usage(argv[0]);
                    return 2;
                }
                b->requests = (unsigned) v;
            } else if (ch == 'r') {
                if (v == 0 || v > UINT64_MAX / 1000 / 8 / 1000000) {
                    xqc_bench_usage(argv[0]);
                    return 2;
                }
                b->rate_bps = v * 1000;
            } else if (ch == 'd') {
                b->delay_us = v;
            } else if (ch == 'q') {
                b->queue_us = v;
            } else if (ch == 'l') {
                if (v >= 1000000) {
                    xqc_bench_usage(argv[0]);
                    return 2;
                }
                b->loss_ppm = (uint32_t) v;
            } else {
                b->seed = v;
            }
            break;
        default:
            xqc_bench_usage(argv[0]);
            return 2;
        }
    }

    for (i = 0; i < XQC_BENCH_PATTERN_LEN; i++) {
        b->pattern[i] = (unsigned char) (i * 31 + (i >> 8));
    }
    b->c2s.rng = b->seed * 2 + 1;
    b->s2c.rng = b->seed * 2 + 2;
    b->now = XQC_BENCH_START_US;

    b->cli.addr.sin_family = AF_INET;
    b->cli.addr.sin_port = htons(40000);
    b->cli.addr.sin_addr.s_addr = htonl(0x7f000001);
    b->cli.out = &b->c2s;
    b->srv.addr.sin_family = AF_INET;
    b->srv.addr.sin_port = htons(8443);
    b->srv.addr.sin_addr.s_addr = htonl(0x7f000001);
    b->srv.out = &b->s2c;

    if (xqc_bench_engine_create(b, &b->srv, XQC_ENGINE_SERVER) != 0
        || xqc_bench_engine_create(b, &b->cli, XQC_ENGINE_CLIENT) != 0)
    {
        fprintf(stderr, "xqc_bench: cannot create the engines\n");
        xqc_bench_close(b);
        return 1;
    }

    if (xqc_bench_connect(b) != 0) {
        fprintf(stderr, "xqc_bench: cannot start the requests\n");
        xqc_bench_close(b);
        return 1;
    }

    ret = xqc_bench_run(b);
    if (ret == 0 && b->done_requests != b->requests) {
        fprintf(stderr, "xqc_bench: %u of %u requests done\n",
                b->done_requests, b->requests);
        ret = -1;
    }

    printf("proto=%s cc=%s requests=%u bytes=%" PRIu64 " loss_ppm=%u"
           " xfer_us=%" PRIu64 " vtime_us=%" PRIu64 " c2s_dgrams=%" PRIu64
           " c2s_bytes=%" PRIu64 " s2c_dgrams=%" PRIu64 " s2c_bytes=%" PRIu64
           " lost=%" PRIu64 " overflow=%" PRIu64 " errors=%" PRIu64 "\n",
           b->hq ? "hq" : "h3", b->cc, b->requests, b->bytes, b->loss_ppm,
           b->xfer_done - XQC_BENCH_START_US, b->now - XQC_BENCH_START_US,
           b->c2s.sent, b->c2s.sent_bytes, b->s2c.sent, b->s2c.sent_bytes,
           b->c2s.lost + b->s2c.lost, b->c2s.overflow + b->s2c.overflow,
           b->errors_logged);

    xqc_bench_close(b);
    if (b->log_file != NULL) {
        fclose(b->log_file);
    }
    return (ret == 0 && !b->failed) ? 0 : 1;
}
