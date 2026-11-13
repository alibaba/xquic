/*
 * CBMC harnesses for the packet header parsers of
 * src/transport/xqc_packet_parser.c.
 *
 * xqc_packet_parse_cid() runs in the engine on every received datagram
 * before any connection exists; the other parsers run on the packet_in of a
 * connection, whose buf/pos/last cover the rest of the datagram.
 */
#include "common.h"

#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_cid.h"

/* defined in xqc_packet_parser.c without a prototype in a header */
xqc_packet_number_t xqc_packet_decode_packet_number(
    xqc_packet_number_t largest_pn, xqc_packet_number_t truncated_pn,
    unsigned pn_nbits);
void xqc_packet_parse_packet_number(uint8_t *pos, xqc_uint_t packet_number_len,
                                    uint64_t *packet_num);

void
harness_parse_cid(void)
{
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= MAXLEN);
    unsigned char *buf = malloc(len);
    __CPROVER_assume(buf != NULL);      /* the engine's receive buffer */
    uint8_t cid_len = nondet_uchar();
    __CPROVER_assume(cid_len <= XQC_MAX_CID_LEN); /* engine configuration */
    xqc_cid_t dcid, scid;

    xqc_int_t ret = xqc_packet_parse_cid(&dcid, &scid, cid_len, buf, len);
    if (ret == XQC_OK) {
        __CPROVER_assert(dcid.cid_len <= XQC_MAX_CID_LEN,
                         "parse_cid: dcid length <= 20");
        if (len > 0 && (buf[0] & 0x80)) {
            __CPROVER_assert(scid.cid_len <= XQC_MAX_CID_LEN,
                             "parse_cid: scid length <= 20");
            __CPROVER_assert(7 + (size_t)dcid.cid_len + scid.cid_len <= len,
                             "parse_cid: both CIDs within the datagram");
        }
    }
    free(buf);
}

/* the connection and engine fields that the header parsers read */
static xqc_connection_t *
mk_conn(void)
{
    xqc_connection_t *c = malloc(sizeof(*c));
    __CPROVER_assume(c != NULL);
    c->conn_err = 0;
    c->conn_close_msg = NULL;
    __CPROVER_assume(c->original_dcid.cid_len <= XQC_MAX_CID_LEN);
    __CPROVER_assume(c->initial_scid.cid_len <= XQC_MAX_CID_LEN);
    __CPROVER_assume(c->scid_set.user_scid.cid_len <= XQC_MAX_CID_LEN);

    xqc_engine_t *engine = malloc(sizeof(*engine));
    __CPROVER_assume(engine != NULL);
    xqc_config_t *config = malloc(sizeof(*config));
    __CPROVER_assume(config != NULL);
    /* the engine's own version list (local configuration): up to 2 here */
    __CPROVER_assume(config->support_version_count <= 2);
    engine->config = config;
    c->engine = engine;
    return c;
}

static void
free_conn(xqc_connection_t *c)
{
    free(c->engine->config);
    free(c->engine);
    free(c);
}

void
harness_parse_long_header(void)
{
    size_t len;
    unsigned char *buf = cbmc_buf(1, &len);
    xqc_connection_t *c = mk_conn();
    xqc_packet_in_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.buf = buf;
    pi.buf_size = len;
    pi.pos = buf;
    pi.last = buf + len;
    size_t dgram = nondet_size_t();
    __CPROVER_assume(dgram >= len && dgram <= 65535);
    pi.datagram_size = dgram;

    xqc_int_t ret = xqc_packet_parse_long_header(c, &pi);
    if (ret == XQC_OK) {
        __CPROVER_assert(pi.pos >= buf && pi.pos <= pi.last
                             && pi.last <= buf + len,
                         "long header: buf <= pos <= last <= end of datagram");
        __CPROVER_assert(pi.pi_pkt.pkt_dcid.cid_len <= XQC_MAX_CID_LEN
                             && pi.pi_pkt.pkt_scid.cid_len <= XQC_MAX_CID_LEN,
                         "long header: CID lengths <= 20");
        if (pi.pi_pkt.pkt_type == XQC_PTYPE_INIT
            || pi.pi_pkt.pkt_type == XQC_PTYPE_HSK
            || pi.pi_pkt.pkt_type == XQC_PTYPE_0RTT)
        {
            /* what xqc_packet_decrypt() relies on */
            __CPROVER_assert(
                pi.pi_pkt.pkt_num_offset + pi.pi_pkt.length <= len,
                "long header: packet number and payload within the datagram");
        }
        if (c->conn_type == XQC_CONN_TYPE_SERVER
            && pi.pi_pkt.pkt_type == XQC_PTYPE_INIT)
        {
            __CPROVER_assert(c->conn_token_len <= XQC_MAX_TOKEN_LEN,
                             "long header: token length <= XQC_MAX_TOKEN_LEN");
        }
    }
    free_conn(c);
    free(buf);
}

void
harness_parse_short_header(void)
{
    size_t len;
    unsigned char *buf = cbmc_buf(1, &len);
    xqc_connection_t *c = mk_conn();
    xqc_packet_in_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.buf = buf;
    pi.buf_size = len;
    pi.pos = buf;
    pi.last = buf + len;

    xqc_int_t ret = xqc_packet_parse_short_header(c, &pi);
    if (ret == XQC_OK) {
        __CPROVER_assert(
            pi.pi_pkt.pkt_num_offset + pi.pi_pkt.length <= len,
            "short header: packet number and payload within the datagram");
    }
    free_conn(c);
    free(buf);
}

void
harness_decode_packet_number(void)
{
    uint64_t largest = nondet_u64();
    /* RFC 9000 Section 12.3: packet numbers stay below 2^62 */
    __CPROVER_assume(largest < ((uint64_t)1 << 62) - ((uint64_t)1 << 32));
    unsigned nbits = nondet_u32();
    __CPROVER_assume(nbits == 8 || nbits == 16 || nbits == 24 || nbits == 32);
    uint64_t truncated = nondet_u64();
    __CPROVER_assume(truncated < ((uint64_t)1 << nbits));

    xqc_packet_number_t pn = xqc_packet_decode_packet_number(largest, truncated,
                                                             nbits);
    __CPROVER_assert((pn & (((uint64_t)1 << nbits) - 1)) == truncated,
                     "packet number: low bits are the truncated packet number");
    __CPROVER_assert(pn < ((uint64_t)1 << 62), "packet number: below 2^62");
}

void
harness_parse_packet_number(void)
{
    unsigned char b[4];
    unsigned len = nondet_u32();
    __CPROVER_assume(len >= 1 && len <= 4);
    uint64_t pn;
    xqc_packet_parse_packet_number(b, len, &pn);
    __CPROVER_assert(len == 4 || pn < ((uint64_t)1 << (8 * len)),
                     "packet number fits its length");
}

void
harness_parse_stateless_reset(void)
{
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= MAXLEN);
    unsigned char *buf = malloc(len);
    __CPROVER_assume(buf != NULL); /* the engine's receive buffer */
    const uint8_t *token = NULL;
    xqc_int_t ret = xqc_packet_parse_stateless_reset(buf, len, &token);
    if (ret == XQC_OK) {
        __CPROVER_assert(token >= buf
                             && token + XQC_STATELESS_RESET_TOKENLEN
                                    <= buf + len,
                         "stateless reset: token within the datagram");
    }
    free(buf);
}

/* ---- the long header packet types, one at a time ------------------------- */

/*
 * xqc_packet_parse_long_header() reads the prefix (first byte, version and
 * both CIDs) and hands the rest to one of these with packet_in->pos after
 * the SCID; buf is the start of the packet.  Each harness starts there:
 * prefix bytes [buf, pos) and type-specific bytes [pos, last).
 */
static void
mk_long_packet(xqc_packet_in_t *pi, unsigned char **bufp, size_t *lenp)
{
    size_t len;
    unsigned char *buf = cbmc_buf(1, &len);
    size_t prefix = nondet_size_t();
    __CPROVER_assume(prefix >= 7 && prefix <= len
                     && prefix <= 7 + 2 * XQC_MAX_CID_LEN);
    memset(pi, 0, sizeof(*pi));
    pi->buf = buf;
    pi->buf_size = len;
    pi->pos = buf + prefix;
    pi->last = buf + len;
    size_t dgram = nondet_size_t();
    __CPROVER_assume(dgram >= len && dgram <= 65535);
    pi->datagram_size = dgram;
    __CPROVER_assume(pi->pi_pkt.pkt_scid.cid_len <= XQC_MAX_CID_LEN);
    __CPROVER_assume(pi->pi_pkt.pkt_dcid.cid_len <= XQC_MAX_CID_LEN);
    *bufp = buf;
    *lenp = len;
}

static void
check_long_ok(const xqc_packet_in_t *pi, const unsigned char *buf, size_t len)
{
    __CPROVER_assert(pi->pos <= pi->last && pi->last <= buf + len,
                     "long packet: pos <= last <= end of datagram");
    __CPROVER_assert(
        pi->pi_pkt.pkt_num_offset + pi->pi_pkt.length <= len,
        "long packet: packet number and payload within the datagram");
}

void
harness_parse_initial(void)
{
    xqc_packet_in_t pi;
    unsigned char *buf;
    size_t len;
    mk_long_packet(&pi, &buf, &len);
    xqc_connection_t *c = mk_conn();
    xqc_int_t ret = xqc_packet_parse_initial(c, &pi);
    if (ret == XQC_OK) {
        check_long_ok(&pi, buf, len);
        if (c->conn_type == XQC_CONN_TYPE_SERVER) {
            __CPROVER_assert(c->conn_token_len <= XQC_MAX_TOKEN_LEN,
                             "Initial: token length <= XQC_MAX_TOKEN_LEN");
        }
    }
    free_conn(c);
    free(buf);
}

void
harness_parse_zero_rtt(void)
{
    xqc_packet_in_t pi;
    unsigned char *buf;
    size_t len;
    mk_long_packet(&pi, &buf, &len);
    xqc_connection_t *c = mk_conn();
    xqc_int_t ret = xqc_packet_parse_zero_rtt(c, &pi);
    if (ret == XQC_OK) {
        check_long_ok(&pi, buf, len);
    }
    free_conn(c);
    free(buf);
}

void
harness_parse_handshake(void)
{
    xqc_packet_in_t pi;
    unsigned char *buf;
    size_t len;
    mk_long_packet(&pi, &buf, &len);
    xqc_connection_t *c = mk_conn();
    xqc_int_t ret = xqc_packet_parse_handshake(c, &pi);
    if (ret == XQC_OK) {
        check_long_ok(&pi, buf, len);
    }
    free_conn(c);
    free(buf);
}

void
harness_parse_retry(void)
{
    xqc_packet_in_t pi;
    unsigned char *buf;
    size_t len;
    mk_long_packet(&pi, &buf, &len);
    xqc_connection_t *c = mk_conn();
    xqc_int_t ret = xqc_packet_parse_retry(c, &pi);
    if (ret == XQC_OK) {
        __CPROVER_assert(pi.pos <= pi.last && pi.last <= buf + len,
                         "Retry: pos <= last <= end of datagram");
        __CPROVER_assert(c->conn_token_len <= XQC_MAX_TOKEN_LEN,
                         "Retry: token length <= XQC_MAX_TOKEN_LEN");
    }
    free_conn(c);
    free(buf);
}

void
harness_parse_version_negotiation(void)
{
    xqc_packet_in_t pi;
    unsigned char *buf;
    size_t len;
    mk_long_packet(&pi, &buf, &len);
    xqc_connection_t *c = mk_conn();
    /* an xqc_proto_version_t value of the connection */
    __CPROVER_assume(c->version >= 0 && c->version <= XQC_VERSION_MAX);
    (void)xqc_packet_parse_version_negotiation(c, &pi);
    free_conn(c);
    free(buf);
}
