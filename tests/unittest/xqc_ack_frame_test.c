/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

/*
 * The ACK frame (RFC 9000 Section 19.3) and the ACK_MP frame, which
 * draft-ietf-quic-multipath-10 Section 7.1 defines as an ACK frame with
 * a Path Identifier, each in a type without and a type with ECN Counts.
 * A frame body gives the same ranges in the four types, a negative packet
 * number is a FRAME_ENCODING_ERROR (RFC 9000 Section 19.3.1), and the ECN
 * Counts are read so that the next frame starts after them.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include "xqc_ack_frame_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_in.h"
#include "xquic/xqc_errno.h"

#define XQC_TEST_VINT_MAX               ((1ULL << 62) - 1)
#define XQC_TEST_PING                   0x01

/* a wire image long enough for every frame these tests build */
#define XQC_TEST_ACK_BUF_LEN            1400

#define XQC_TEST_ACK_FUZZ_SEED          0x9e3779b97f4a7c15ULL
#define XQC_TEST_ACK_FUZZ_ROUNDS        4000
#define XQC_TEST_ACK_FUZZ_MAX_RANGES    80

typedef struct xqc_test_ack_kind_s {
    const char                 *name;
    unsigned char               type[4];    /* shortest encoding */
    size_t                      type_len;
    xqc_bool_t                  mp;         /* Path Identifier first */
    xqc_bool_t                  ecn;        /* ECN Counts last */
} xqc_test_ack_kind_t;

static const xqc_test_ack_kind_t xqc_test_ack_kinds[] = {
    { "ACK",        { 0x02 },                   1, XQC_FALSE, XQC_FALSE },
    { "ACK_ECN",    { 0x03 },                   1, XQC_FALSE, XQC_TRUE  },
    { "ACK_MP",     { 0x95, 0x22, 0x8c, 0x00 }, 4, XQC_TRUE,  XQC_FALSE },
    { "ACK_MP_ECN", { 0x95, 0x22, 0x8c, 0x01 }, 4, XQC_TRUE,  XQC_TRUE  },
};

#define XQC_TEST_ACK_KIND_N \
    (sizeof(xqc_test_ack_kinds) / sizeof(xqc_test_ack_kinds[0]))

/* ECT0 Count 64 in two bytes, ECT1 Count 2, ECN-CE Count 1 */
static const unsigned char xqc_test_ecn_counts[] = { 0x40, 0x40, 0x02, 0x01 };

/*
 * Golden frames, each followed by a PING: Path Identifier 1 for ACK_MP,
 * Largest Acknowledged 10, ACK Delay 5, ACK Range Count 1, First ACK
 * Range 2 (10..8), Gap 1, ACK Range Length 2 (5..3), and for the ECN
 * types the counts above.
 */
static const unsigned char xqc_test_golden_ack[] = {
    0x02, 0x0a, 0x05, 0x01, 0x02, 0x01, 0x02,
    0x01
};

static const unsigned char xqc_test_golden_ack_ecn[] = {
    0x03, 0x0a, 0x05, 0x01, 0x02, 0x01, 0x02, 0x40, 0x40, 0x02, 0x01,
    0x01
};

static const unsigned char xqc_test_golden_ack_mp[] = {
    0x95, 0x22, 0x8c, 0x00, 0x01, 0x0a, 0x05, 0x01, 0x02, 0x01, 0x02,
    0x01
};

static const unsigned char xqc_test_golden_ack_mp_ecn[] = {
    0x95, 0x22, 0x8c, 0x01, 0x01, 0x0a, 0x05, 0x01, 0x02, 0x01, 0x02,
    0x40, 0x40, 0x02, 0x01,
    0x01
};

typedef struct xqc_test_ack_golden_s {
    const unsigned char        *wire;
    size_t                      len;        /* with the PING */
} xqc_test_ack_golden_t;

/* in the order of xqc_test_ack_kinds */
static const xqc_test_ack_golden_t xqc_test_ack_golden[] = {
    { xqc_test_golden_ack,        sizeof(xqc_test_golden_ack) },
    { xqc_test_golden_ack_ecn,    sizeof(xqc_test_golden_ack_ecn) },
    { xqc_test_golden_ack_mp,     sizeof(xqc_test_golden_ack_mp) },
    { xqc_test_golden_ack_mp_ecn, sizeof(xqc_test_golden_ack_mp_ecn) },
};

_Static_assert(sizeof(xqc_test_ack_golden) / sizeof(xqc_test_ack_golden[0])
               == XQC_TEST_ACK_KIND_N, "one golden frame per ACK type");

/*
 * Frame bodies from Largest Acknowledged on, around the packet number 0
 * boundary of RFC 9000 Section 19.3.1: Largest Acknowledged, ACK Delay,
 * ACK Range Count, First ACK Range, then Gap and ACK Range Length.
 */
typedef struct xqc_test_ack_body_s {
    const char                 *name;
    unsigned char               body[6];
    size_t                      len;
    xqc_bool_t                  valid;
} xqc_test_ack_body_t;

static const xqc_test_ack_body_t xqc_test_ack_boundaries[] = {
    { "first range to 0",
      { 0x05, 0x00, 0x00, 0x05 }, 4, XQC_TRUE },
    { "first range below 0",
      { 0x00, 0x00, 0x00, 0x05 }, 4, XQC_FALSE },
    { "gap to 0",
      { 0x0a, 0x00, 0x01, 0x00, 0x08, 0x00 }, 6, XQC_TRUE },
    { "gap below 0",
      { 0x0a, 0x00, 0x01, 0x00, 0x09, 0x00 }, 6, XQC_FALSE },
    { "no room for a gap",
      { 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 }, 6, XQC_FALSE },
    { "range to 0",
      { 0x0a, 0x00, 0x01, 0x00, 0x00, 0x08 }, 6, XQC_TRUE },
    { "range below 0",
      { 0x0a, 0x00, 0x01, 0x00, 0x00, 0x09 }, 6, XQC_FALSE },
};

#define XQC_TEST_ACK_BOUNDARY_N \
    (sizeof(xqc_test_ack_boundaries) / sizeof(xqc_test_ack_boundaries[0]))

typedef struct xqc_test_ack_model_s {
    const xqc_test_ack_kind_t  *kind;
    uint64_t                    path_id;
    uint64_t                    largest;
    uint64_t                    delay;
    uint64_t                    count;
    uint64_t                    first;
    uint64_t                    gap[XQC_TEST_ACK_FUZZ_MAX_RANGES];
    uint64_t                    length[XQC_TEST_ACK_FUZZ_MAX_RANGES];
    uint64_t                    ecn[3];
} xqc_test_ack_model_t;

typedef struct xqc_test_ack_expect_s {
    xqc_bool_t                  valid;
    uint64_t                    bad_range;  /* 0: First ACK Range */
    unsigned                    n_ranges;
    xqc_pktno_range_t           ranges[XQC_MAX_ACK_RANGE_CNT];
} xqc_test_ack_expect_t;

static xqc_connection_t *xqc_test_ack_conn(void);
static void xqc_test_ack_packet_in(xqc_packet_in_t *pi, unsigned char *buf,
    size_t len);
static xqc_int_t xqc_test_ack_parse(xqc_connection_t *conn,
    const xqc_test_ack_kind_t *kind, xqc_packet_in_t *pi, uint64_t *path_id,
    xqc_ack_info_t *ack_info);
static xqc_frame_type_bit_t xqc_test_ack_bit(
    const xqc_test_ack_kind_t *kind);
static size_t xqc_test_ack_build(unsigned char *buf,
    const xqc_test_ack_kind_t *kind, unsigned char path_id,
    const unsigned char *body, size_t body_len, xqc_bool_t ecn_counts);
static void xqc_test_ack_refused(xqc_connection_t *conn,
    const xqc_packet_in_t *pi, const unsigned char *buf, xqc_int_t ret,
    xqc_int_t expected);
static uint64_t xqc_test_rand(uint64_t *state);
static uint64_t xqc_test_rand_below(uint64_t *state, uint64_t bound);
static uint64_t xqc_test_rand_upto(uint64_t *state, uint64_t max);
static unsigned char *xqc_test_put_vint(uint64_t *state, unsigned char *p,
    uint64_t value);
static void xqc_test_ack_model_gen(uint64_t *state,
    xqc_test_ack_model_t *m);
static void xqc_test_ack_model_eval(const xqc_test_ack_model_t *m,
    xqc_test_ack_expect_t *e);
static size_t xqc_test_ack_model_encode(uint64_t *state,
    const xqc_test_ack_model_t *m, const xqc_test_ack_expect_t *e,
    unsigned char *buf, size_t *detect);
static xqc_bool_t xqc_test_ack_model_check(xqc_connection_t *conn,
    const xqc_test_ack_model_t *m, const xqc_test_ack_expect_t *e,
    const xqc_packet_in_t *pi, const unsigned char *wire, size_t len,
    xqc_int_t ret, xqc_int_t expected, uint64_t path_id,
    const xqc_ack_info_t *ack_info);


static xqc_connection_t *
xqc_test_ack_conn(void)
{
    xqc_connection_t *conn;

    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    return conn;
}


static void
xqc_test_ack_packet_in(xqc_packet_in_t *pi, unsigned char *buf, size_t len)
{
    memset(pi, 0, sizeof(*pi));
    pi->pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi->pi_pkt.pkt_pns = XQC_PNS_APP_DATA;
    pi->pos = buf;
    pi->last = buf + len;
}


/* parse with the function the frame dispatcher calls for the type */
static xqc_int_t
xqc_test_ack_parse(xqc_connection_t *conn, const xqc_test_ack_kind_t *kind,
    xqc_packet_in_t *pi, uint64_t *path_id, xqc_ack_info_t *ack_info)
{
    memset(ack_info, 0, sizeof(*ack_info));
    *path_id = 0;

    if (kind->mp) {
        return xqc_parse_ack_mp_frame(pi, conn, path_id, ack_info);
    }

    return xqc_parse_ack_frame(pi, conn, ack_info);
}


static xqc_frame_type_bit_t
xqc_test_ack_bit(const xqc_test_ack_kind_t *kind)
{
    return kind->mp ? XQC_FRAME_BIT_ACK_MP : XQC_FRAME_BIT_ACK;
}


/* the type, the Path Identifier of ACK_MP, body, then the ECN Counts */
static size_t
xqc_test_ack_build(unsigned char *buf, const xqc_test_ack_kind_t *kind,
    unsigned char path_id, const unsigned char *body, size_t body_len,
    xqc_bool_t ecn_counts)
{
    unsigned char *p = buf;

    memcpy(p, kind->type, kind->type_len);
    p += kind->type_len;

    if (kind->mp) {
        *p++ = path_id;     /* one-byte varint */
    }

    memcpy(p, body, body_len);
    p += body_len;

    if (kind->ecn && ecn_counts) {
        memcpy(p, xqc_test_ecn_counts, sizeof(xqc_test_ecn_counts));
        p += sizeof(xqc_test_ecn_counts);
    }

    return p - buf;
}


/* the frame is refused and the packet is left where it was */
static void
xqc_test_ack_refused(xqc_connection_t *conn, const xqc_packet_in_t *pi,
    const unsigned char *buf, xqc_int_t ret, xqc_int_t expected)
{
    CU_ASSERT_EQUAL(ret, expected);
    CU_ASSERT_PTR_EQUAL(pi->pos, buf);
    CU_ASSERT_EQUAL(pi->pi_frame_types, 0);

    if (expected == -XQC_EILLEGAL_FRAME) {
        CU_ASSERT_EQUAL(conn->conn_err, TRA_FRAME_ENCODING_ERROR);
        CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    } else {
        CU_ASSERT_EQUAL(conn->conn_err, 0);
    }
}


/* the four types give the same ranges and stop before the next frame */
void
xqc_test_ack_frame_golden(void)
{
    const xqc_test_ack_kind_t *kind;
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_ack_info_t ack_info;
    unsigned char buf[XQC_TEST_ACK_BUF_LEN];
    uint64_t path_id;
    size_t i, len;
    xqc_int_t ret;

    for (i = 0; i < XQC_TEST_ACK_KIND_N; i++) {
        kind = &xqc_test_ack_kinds[i];
        len = xqc_test_ack_golden[i].len;
        memcpy(buf, xqc_test_ack_golden[i].wire, len);

        conn = xqc_test_ack_conn();
        xqc_test_ack_packet_in(&pi, buf, len);

        ret = xqc_test_ack_parse(conn, kind, &pi, &path_id, &ack_info);

        CU_ASSERT_EQUAL(ret, XQC_OK);
        CU_ASSERT_PTR_EQUAL(pi.pos, buf + len - 1);
        CU_ASSERT_EQUAL(buf[len - 1], XQC_TEST_PING);
        CU_ASSERT_EQUAL(pi.pi_frame_types, xqc_test_ack_bit(kind));
        CU_ASSERT_EQUAL(path_id, kind->mp ? 1 : 0);
        CU_ASSERT_EQUAL(ack_info.path_id, path_id);
        CU_ASSERT_EQUAL(ack_info.pns, XQC_PNS_APP_DATA);
        CU_ASSERT_EQUAL(ack_info.largest_acked, 10);
        CU_ASSERT_EQUAL(ack_info.ack_delay,
                        5ULL << conn->remote_settings.ack_delay_exponent);
        CU_ASSERT_EQUAL(ack_info.n_ranges, 2);
        CU_ASSERT_EQUAL(ack_info.ranges[0].high, 10);
        CU_ASSERT_EQUAL(ack_info.ranges[0].low, 8);
        CU_ASSERT_EQUAL(ack_info.ranges[1].high, 5);
        CU_ASSERT_EQUAL(ack_info.ranges[1].low, 3);

        xqc_engine_destroy(conn->engine);
    }
}


/*
 * The frame loop parses the frame after the ECN Counts of ACK_ECN and of
 * ACK_MP with ECN: the second byte of the ECT0 Count, 0x40, is no frame
 * type of xquic and drops the packet if read as one.
 */
void
xqc_test_ack_frame_next_frame(void)
{
    static const unsigned char body[] = { 0x0a, 0x05, 0x01, 0x02, 0x01, 0x02 };
    const xqc_test_ack_kind_t *kind;
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    unsigned char buf[XQC_TEST_ACK_BUF_LEN];
    size_t i, len;
    xqc_int_t ret;

    for (i = 0; i < XQC_TEST_ACK_KIND_N; i++) {
        kind = &xqc_test_ack_kinds[i];

        conn = xqc_test_ack_conn();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn->conn_initial_path);
        conn->enable_multipath = XQC_CONN_MP_ENABLED;
        conn->conn_settings.multipath_version = XQC_MULTIPATH_10;
        conn->conn_initial_path->path_state = XQC_PATH_STATE_ACTIVE;

        /* path ID 0: the initial path */
        len = xqc_test_ack_build(buf, kind, 0, body, sizeof(body), XQC_TRUE);
        buf[len++] = XQC_TEST_PING;
        xqc_test_ack_packet_in(&pi, buf, len);

        ret = xqc_process_frames(conn, &pi);

        CU_ASSERT_EQUAL(ret, XQC_OK);
        CU_ASSERT_PTR_EQUAL(pi.pos, pi.last);
        CU_ASSERT_EQUAL(pi.pi_frame_types,
                        xqc_test_ack_bit(kind) | XQC_FRAME_BIT_PING);
        CU_ASSERT_EQUAL(conn->conn_err, 0);

        xqc_engine_destroy(conn->engine);
    }
}


/*
 * RFC 9000 Section 19.3.1: "If any computed packet number is negative, an
 * endpoint MUST generate a connection error of type FRAME_ENCODING_ERROR".
 * Every ACK type, also for a range past the XQC_MAX_ACK_RANGE_CNT kept.
 */
void
xqc_test_ack_frame_negative_pn(void)
{
    const xqc_test_ack_kind_t *kind;
    const xqc_test_ack_body_t *b;
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_ack_info_t ack_info;
    unsigned char buf[XQC_TEST_ACK_BUF_LEN];
    unsigned char past_kept[6 + 70 * 2];
    unsigned char *p;
    uint64_t path_id;
    size_t i, j, len;
    xqc_int_t ret;

    /*
     * Largest Acknowledged 200, ACK Range Count 70, First ACK Range 0:
     * ranges of one packet at 200, 198, ..., 62, then a 70th range of 62
     * packets from 60 down.
     */
    p = past_kept;
    *p++ = 0x40;
    *p++ = 0xc8;
    *p++ = 0x00;
    *p++ = 0x40;
    *p++ = 0x46;
    *p++ = 0x00;
    for (j = 0; j < 69; j++) {
        *p++ = 0x00;
        *p++ = 0x00;
    }
    *p++ = 0x00;
    *p++ = 0x3d;
    CU_ASSERT_EQUAL((size_t) (p - past_kept), sizeof(past_kept));

    for (i = 0; i < XQC_TEST_ACK_KIND_N; i++) {
        kind = &xqc_test_ack_kinds[i];

        for (j = 0; j < XQC_TEST_ACK_BOUNDARY_N; j++) {
            b = &xqc_test_ack_boundaries[j];

            conn = xqc_test_ack_conn();
            len = xqc_test_ack_build(buf, kind, 1, b->body, b->len, XQC_TRUE);
            buf[len++] = XQC_TEST_PING;
            xqc_test_ack_packet_in(&pi, buf, len);

            ret = xqc_test_ack_parse(conn, kind, &pi, &path_id, &ack_info);

            if (b->valid) {
                CU_ASSERT_EQUAL(ret, XQC_OK);
                CU_ASSERT_PTR_EQUAL(pi.pos, pi.last - 1);
                CU_ASSERT(ack_info.n_ranges > 0
                          && ack_info.ranges[ack_info.n_ranges - 1].low == 0);
                CU_ASSERT_EQUAL(conn->conn_err, 0);

            } else {
                xqc_test_ack_refused(conn, &pi, buf, ret,
                                     -XQC_EILLEGAL_FRAME);
            }

            xqc_engine_destroy(conn->engine);
        }

        conn = xqc_test_ack_conn();
        len = xqc_test_ack_build(buf, kind, 1, past_kept, sizeof(past_kept),
                                 XQC_TRUE);
        xqc_test_ack_packet_in(&pi, buf, len);

        ret = xqc_test_ack_parse(conn, kind, &pi, &path_id, &ack_info);

        xqc_test_ack_refused(conn, &pi, buf, ret, -XQC_EILLEGAL_FRAME);
        xqc_engine_destroy(conn->engine);
    }
}


/*
 * A frame cut anywhere, the ECN Counts included, is refused without
 * reading past the end of the packet (the bytes are copied to a heap
 * block of the cut length, so that ASan sees reads beyond it).
 */
void
xqc_test_ack_frame_truncated(void)
{
    const xqc_test_ack_kind_t *kind;
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_ack_info_t ack_info;
    unsigned char *cut;
    uint64_t path_id;
    size_t i, len, frame_len;
    xqc_int_t ret;

    conn = xqc_test_ack_conn();

    for (i = 0; i < XQC_TEST_ACK_KIND_N; i++) {
        kind = &xqc_test_ack_kinds[i];
        frame_len = xqc_test_ack_golden[i].len - 1;

        for (len = 0; len < frame_len; len++) {
            cut = malloc(len > 0 ? len : 1);
            CU_ASSERT_PTR_NOT_NULL_FATAL(cut);
            memcpy(cut, xqc_test_ack_golden[i].wire, len);
            xqc_test_ack_packet_in(&pi, cut, len);

            ret = xqc_test_ack_parse(conn, kind, &pi, &path_id, &ack_info);

            xqc_test_ack_refused(conn, &pi, cut, ret, -XQC_EVINTREAD);
            free(cut);
        }
    }

    xqc_engine_destroy(conn->engine);
}


/*
 * More ACK Ranges than XQC_MAX_ACK_RANGE_CNT: the first ones are kept,
 * the others read, and the ECN Counts after them.  An ACK Range Count
 * larger than the packet can hold stops at the end of the packet.
 */
void
xqc_test_ack_frame_range_count(void)
{
    const xqc_test_ack_kind_t *kind;
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_ack_info_t ack_info;
    unsigned char buf[XQC_TEST_ACK_BUF_LEN];
    unsigned char many[6 + 100 * 2];
    unsigned char huge[11 + 2 * 2];
    unsigned char *p;
    uint64_t path_id;
    size_t i, j, len;
    xqc_int_t ret;

    /* Largest 1000, ACK Range Count 100: one packet at 1000, 998, ... */
    p = many;
    *p++ = 0x43;
    *p++ = 0xe8;
    *p++ = 0x00;
    *p++ = 0x40;
    *p++ = 0x64;
    *p++ = 0x00;
    for (j = 0; j < 100; j++) {
        *p++ = 0x00;
        *p++ = 0x00;
    }
    CU_ASSERT_EQUAL((size_t) (p - many), sizeof(many));

    /* Largest 10, ACK Range Count 2^62 - 1, two ranges present */
    p = huge;
    *p++ = 0x0a;
    *p++ = 0x00;
    memset(p, 0xff, 8);
    p += 8;
    *p++ = 0x00;
    for (j = 0; j < 2; j++) {
        *p++ = 0x00;
        *p++ = 0x00;
    }
    CU_ASSERT_EQUAL((size_t) (p - huge), sizeof(huge));

    for (i = 0; i < XQC_TEST_ACK_KIND_N; i++) {
        kind = &xqc_test_ack_kinds[i];

        conn = xqc_test_ack_conn();
        len = xqc_test_ack_build(buf, kind, 1, many, sizeof(many), XQC_TRUE);
        buf[len++] = XQC_TEST_PING;
        xqc_test_ack_packet_in(&pi, buf, len);

        ret = xqc_test_ack_parse(conn, kind, &pi, &path_id, &ack_info);

        CU_ASSERT_EQUAL(ret, XQC_OK);
        CU_ASSERT_PTR_EQUAL(pi.pos, pi.last - 1);
        CU_ASSERT_EQUAL(ack_info.n_ranges, XQC_MAX_ACK_RANGE_CNT);
        for (j = 0; j < XQC_MAX_ACK_RANGE_CNT; j++) {
            CU_ASSERT_EQUAL(ack_info.ranges[j].high, 1000 - 2 * j);
            CU_ASSERT_EQUAL(ack_info.ranges[j].low, 1000 - 2 * j);
        }

        len = xqc_test_ack_build(buf, kind, 1, huge, sizeof(huge), XQC_FALSE);
        xqc_test_ack_packet_in(&pi, buf, len);

        ret = xqc_test_ack_parse(conn, kind, &pi, &path_id, &ack_info);

        xqc_test_ack_refused(conn, &pi, buf, ret, -XQC_EVINTREAD);
        xqc_engine_destroy(conn->engine);
    }
}


/* xorshift64*: deterministic, so a failing round can be replayed */
static uint64_t
xqc_test_rand(uint64_t *state)
{
    uint64_t x = *state;

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545f4914f6cdd1dULL;
}


static uint64_t
xqc_test_rand_below(uint64_t *state, uint64_t bound)
{
    return xqc_test_rand(state) % bound;
}


/* a value in [0, max], small most of the time, max itself sometimes */
static uint64_t
xqc_test_rand_upto(uint64_t *state, uint64_t max)
{
    uint64_t r = xqc_test_rand_below(state, 16);

    if (r == 0) {
        return max;
    }

    if (r < 4) {
        return xqc_test_rand_below(state, max + 1);
    }

    return xqc_test_rand_below(state, (max < 3 ? max : 3) + 1);
}


/*
 * Write value as a varint, in its shortest encoding or, sometimes, in a
 * longer one (RFC 9000 Section 16 allows both).
 */
static unsigned char *
xqc_test_put_vint(uint64_t *state, unsigned char *p, uint64_t value)
{
    unsigned two_bit, len, i;

    two_bit = value < (1ULL << 6) ? 0 : value < (1ULL << 14) ? 1
              : value < (1ULL << 30) ? 2 : 3;
    while (two_bit < 3 && xqc_test_rand_below(state, 4) == 0) {
        two_bit++;
    }

    len = 1u << two_bit;
    for (i = 0; i < len; i++) {
        p[i] = (unsigned char) (value >> (8 * (len - 1 - i)));
    }
    p[0] |= (unsigned char) (two_bit << 6);

    return p + len;
}


/*
 * A random frame.  Three times in four all its ranges stay at or above 0,
 * each leaving room for the ones after it; otherwise one range, the bad
 * one, goes below 0 and the fields after it are random.
 */
static void
xqc_test_ack_model_gen(uint64_t *state, xqc_test_ack_model_t *m)
{
    static const uint64_t edges[] = {
        0, 1, 2, 3, 63, 64, 16383, 16384, XQC_TEST_VINT_MAX
    };
    const uint64_t n_edges = sizeof(edges) / sizeof(edges[0]);
    const uint64_t max = XQC_TEST_VINT_MAX;
    uint64_t bad, n_valid, left, prev_low, high, i;

    m->kind = &xqc_test_ack_kinds[xqc_test_rand_below(state,
                                                      XQC_TEST_ACK_KIND_N)];
    m->path_id = xqc_test_rand_upto(state, max);
    m->delay = xqc_test_rand_upto(state, max);
    m->count = xqc_test_rand_below(state, 2) == 0
               ? xqc_test_rand_below(state, 4)
               : xqc_test_rand_below(state, XQC_TEST_ACK_FUZZ_MAX_RANGES + 1);

    switch (xqc_test_rand_below(state, 4)) {
    case 0:
        m->largest = xqc_test_rand_below(state, 200);
        break;
    case 1:
        m->largest = xqc_test_rand_below(state, 1ULL << 14);
        break;
    case 2:
        m->largest = xqc_test_rand_below(state, max + 1);
        break;
    default:
        m->largest = edges[xqc_test_rand_below(state, n_edges)];
        break;
    }

    /* range 0 is the First ACK Range; no bad range is count + 1 */
    bad = xqc_test_rand_below(state, 4) == 0
          ? xqc_test_rand_below(state, m->count + 1) : m->count + 1;
    n_valid = bad < m->count + 1 ? bad : m->count + 1;

    /* a range and a gap of one packet each for every valid range after 0 */
    if (n_valid > 0 && m->largest < 2 * (n_valid - 1)) {
        m->largest = 2 * (n_valid - 1) + xqc_test_rand_below(state, 64);
    }

    if (bad == 0 && m->largest < max) {
        m->first = m->largest + 1
                   + xqc_test_rand_upto(state, max - m->largest - 1);

    } else {
        left = n_valid > 0 ? n_valid - 1 : 0;
        m->first = xqc_test_rand_upto(state, m->largest - 2 * left);
    }

    prev_low = m->largest - m->first;   /* used up to range bad only */

    for (i = 1; i <= m->count; i++) {
        if (i < n_valid) {
            left = n_valid - 1 - i;
            m->gap[i - 1] = xqc_test_rand_upto(state, prev_low - 2 - 2 * left);
            high = prev_low - m->gap[i - 1] - 2;
            m->length[i - 1] = xqc_test_rand_upto(state, high - 2 * left);
            prev_low = high - m->length[i - 1];

        } else if (i == bad && prev_low >= 2
                   && xqc_test_rand_below(state, 2) == 0)
        {
            /* smallest = largest - ack_range below 0 */
            m->gap[i - 1] = xqc_test_rand_upto(state, prev_low - 2);
            high = prev_low - m->gap[i - 1] - 2;
            m->length[i - 1] = high + 1
                               + xqc_test_rand_upto(state, max - high - 1);

        } else if (i == bad) {
            /* largest = previous_smallest - gap - 2 below 0 */
            m->gap[i - 1] = prev_low < 2
                            ? xqc_test_rand_upto(state, max)
                            : prev_low - 1
                              + xqc_test_rand_upto(state, max - prev_low + 1);
            m->length[i - 1] = xqc_test_rand_upto(state, max);

        } else {
            m->gap[i - 1] = xqc_test_rand_upto(state, max);
            m->length[i - 1] = xqc_test_rand_upto(state, max);
        }
    }

    for (i = 0; i < 3; i++) {
        m->ecn[i] = xqc_test_rand_upto(state, max);
    }
}


/*
 * The formulas of RFC 9000 Section 19.3.1 in signed arithmetic, which
 * holds every value since varints are below 2^62.
 */
static void
xqc_test_ack_model_eval(const xqc_test_ack_model_t *m,
    xqc_test_ack_expect_t *e)
{
    int64_t high, low;
    uint64_t i;

    high = (int64_t) m->largest;
    low = high - (int64_t) m->first;
    e->n_ranges = 0;

    for (i = 0; ; i++) {
        /* low <= high, so a negative high gives a negative low */
        if (low < 0) {
            e->valid = XQC_FALSE;
            e->bad_range = i;
            return;
        }

        if (e->n_ranges < XQC_MAX_ACK_RANGE_CNT) {
            e->ranges[e->n_ranges].high = (xqc_packet_number_t) high;
            e->ranges[e->n_ranges].low = (xqc_packet_number_t) low;
            e->n_ranges++;
        }

        if (i == m->count) {
            break;
        }

        /* largest = previous_smallest - gap - 2, smallest = largest - len */
        high = low - (int64_t) m->gap[i] - 2;
        low = high - (int64_t) m->length[i];
    }

    e->valid = XQC_TRUE;
    e->bad_range = 0;
}


/*
 * The wire image of m; *detect is where a refused frame is found out: the
 * end of the fields of its first range below 0.
 */
static size_t
xqc_test_ack_model_encode(uint64_t *state, const xqc_test_ack_model_t *m,
    const xqc_test_ack_expect_t *e, unsigned char *buf, size_t *detect)
{
    unsigned char *p = buf;
    uint64_t i;

    memcpy(p, m->kind->type, m->kind->type_len);
    p += m->kind->type_len;

    if (m->kind->mp) {
        p = xqc_test_put_vint(state, p, m->path_id);
    }

    p = xqc_test_put_vint(state, p, m->largest);
    p = xqc_test_put_vint(state, p, m->delay);
    p = xqc_test_put_vint(state, p, m->count);
    p = xqc_test_put_vint(state, p, m->first);

    *detect = 0;
    if (!e->valid && e->bad_range == 0) {
        *detect = p - buf;
    }

    for (i = 0; i < m->count; i++) {
        p = xqc_test_put_vint(state, p, m->gap[i]);
        p = xqc_test_put_vint(state, p, m->length[i]);

        if (!e->valid && e->bad_range == i + 1) {
            *detect = p - buf;
        }
    }

    if (m->kind->ecn) {
        for (i = 0; i < 3; i++) {
            p = xqc_test_put_vint(state, p, m->ecn[i]);
        }
    }

    return p - buf;
}


static xqc_bool_t
xqc_test_ack_model_check(xqc_connection_t *conn,
    const xqc_test_ack_model_t *m, const xqc_test_ack_expect_t *e,
    const xqc_packet_in_t *pi, const unsigned char *wire, size_t len,
    xqc_int_t ret, xqc_int_t expected, uint64_t path_id,
    const xqc_ack_info_t *ack_info)
{
    unsigned i;

    if (ret != expected) {
        return XQC_FALSE;
    }

    if (ret != XQC_OK) {
        return pi->pos == wire && pi->pi_frame_types == 0
               && conn->conn_err == (ret == -XQC_EILLEGAL_FRAME
                                     ? TRA_FRAME_ENCODING_ERROR : 0);
    }

    if (pi->pos != wire + len
        || pi->pi_frame_types != xqc_test_ack_bit(m->kind)
        || path_id != (m->kind->mp ? m->path_id : 0)
        || ack_info->path_id != path_id
        || ack_info->largest_acked != m->largest
        || ack_info->ack_delay
           != m->delay << conn->remote_settings.ack_delay_exponent
        || ack_info->n_ranges != e->n_ranges
        || conn->conn_err != 0)
    {
        return XQC_FALSE;
    }

    for (i = 0; i < e->n_ranges; i++) {
        if (ack_info->ranges[i].high != e->ranges[i].high
            || ack_info->ranges[i].low != e->ranges[i].low)
        {
            return XQC_FALSE;
        }
    }

    return XQC_TRUE;
}


/*
 * Structure-aware fuzzing with a fixed seed: random ACK frames of the four
 * types, valid or with a range below 0, in random varint lengths, cut
 * short sometimes, parsed and compared with the model above.
 */
void
xqc_test_ack_frame_fuzz(void)
{
    xqc_test_ack_model_t m;
    xqc_test_ack_expect_t e;
    unsigned char buf[XQC_TEST_ACK_BUF_LEN];
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_ack_info_t ack_info;
    unsigned char *wire;
    uint64_t state, path_id;
    size_t len, cut, detect, failed;
    xqc_int_t ret, expected;
    xqc_bool_t ok;
    int round;

    state = XQC_TEST_ACK_FUZZ_SEED;
    failed = 0;
    conn = xqc_test_ack_conn();

    for (round = 0; round < XQC_TEST_ACK_FUZZ_ROUNDS; round++) {
        xqc_test_ack_model_gen(&state, &m);
        xqc_test_ack_model_eval(&m, &e);
        len = xqc_test_ack_model_encode(&state, &m, &e, buf, &detect);

        if (xqc_test_rand_below(&state, 5) == 0) {
            cut = xqc_test_rand_below(&state, len);
            expected = !e.valid && cut >= detect
                       ? -XQC_EILLEGAL_FRAME : -XQC_EVINTREAD;

        } else {
            buf[len] = XQC_TEST_PING;
            cut = len + 1;
            expected = e.valid ? XQC_OK : -XQC_EILLEGAL_FRAME;
        }

        /* an exact heap block, so that ASan sees reads past the packet */
        wire = malloc(cut);
        CU_ASSERT_PTR_NOT_NULL_FATAL(wire);
        memcpy(wire, buf, cut);
        xqc_test_ack_packet_in(&pi, wire, cut);

        ret = xqc_test_ack_parse(conn, m.kind, &pi, &path_id, &ack_info);

        ok = xqc_test_ack_model_check(conn, &m, &e, &pi, wire, len, ret,
                                      expected, path_id, &ack_info);
        CU_ASSERT(ok);
        if (!ok && failed++ == 0) {
            printf("\nxqc_test_ack_frame_fuzz: round %d, %s, ret %d,"
                   " expected %d\n", round, m.kind->name, (int) ret,
                   (int) expected);
        }

        free(wire);

        if (conn->conn_err != 0) {
            xqc_engine_destroy(conn->engine);
            conn = xqc_test_ack_conn();
        }
    }

    xqc_engine_destroy(conn->engine);
}
