/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Reverse-validation of the RFC 9000 Section 12.2 fix: lighting up the
 * coalesced-DCID-mismatch branch in xqc_conn_process_packet, while keeping
 * the happy path quiet.
 *
 * The trick is to encrypt each Initial under the *same* client-side Initial
 * keys (which were derived from the original DCID) and only flip bytes in
 * the wire-level DCID field. The AEAD AAD is the on-wire header, so as long
 * as both endpoints see the same bytes the tag still validates - the only
 * thing that diverges is what xqc_packet_parse_long_header records into
 * pi_pkt.pkt_dcid, which is exactly what the new validation inspects.
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include <stdint.h>

#include "xqc_coalesced_test.h"

#include "xquic/xquic.h"
#include "xquic/xquic_typedef.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_cid.h"


extern xqc_usec_t xqc_now(void);


/* Each Initial must be at least 1200 bytes on the server's view; pad to
 * 1300 to leave headroom for variable-length header fields. */
#define COALESCED_TEST_PKT_TARGET 1300


typedef struct coalesced_ctx_s {
    xqc_engine_t       *engine;
    xqc_connection_t   *c;
    xqc_cid_t           cid;
    unsigned char       buf[2048];
    size_t              buf_len;
} coalesced_ctx_t;


static ssize_t
coalesced_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data)
{
    coalesced_ctx_t *ctx = (coalesced_ctx_t *)conn_user_data;
    if (size > sizeof(ctx->buf)) {
        size = sizeof(ctx->buf);
    }
    memcpy(ctx->buf, buf, size);
    ctx->buf_len = size;
    return size;
}

static int
coalesced_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    coalesced_ctx_t *ctx = (coalesced_ctx_t *)user_data;
    ctx->c = conn;
    memcpy(&ctx->cid, cid, sizeof(xqc_cid_t));
    xqc_conn_set_alp_user_data(conn, ctx);
    return 0;
}

static void
coalesced_set_event_timer(xqc_msec_t wake_after, void *engine_user_data)
{
    return;
}

static xqc_engine_t *
coalesced_create_engine(coalesced_ctx_t *ctx, xqc_engine_type_t etype)
{
    xqc_engine_ssl_config_t ssl_config;
    memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.private_key_file = "./server.key";
    ssl_config.cert_file        = "./server.crt";
    ssl_config.ciphers          = XQC_TLS_CIPHERS;
    ssl_config.groups           = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cb = {
        .set_event_timer = coalesced_set_event_timer,
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = coalesced_write_socket,
    };

    xqc_app_proto_callbacks_t alp_cbs = {
        .conn_cbs.conn_create_notify = coalesced_conn_create_notify,
    };

    xqc_engine_t *engine = xqc_engine_create(etype, NULL, &ssl_config,
                                             &engine_cb, &tcbs, ctx);
    if (engine == NULL) {
        return NULL;
    }
    xqc_engine_register_alpn(engine, "transport", 9, &alp_cbs, NULL);
    return engine;
}


/*
 * Build a single Initial packet with a caller-supplied DCID, padding-only
 * payload, and a chosen packet number. Returns 0 on failure, otherwise the
 * size written into out_buf (which must be at least 2048 bytes).
 *
 * The encryption is performed against cli_conn so the keys come from the
 * client's Initial secret; the DCID we put in the header is purely a wire
 * value that ends up in the AEAD AAD on both sides.
 */
static size_t
build_initial_pkt(xqc_connection_t *cli_conn,
                  const unsigned char *dcid_buf, uint8_t dcid_len,
                  xqc_packet_number_t pkt_num,
                  uint8_t *out_buf, size_t out_buf_cap)
{
    xqc_packet_out_t *po = xqc_packet_out_create(2048);
    if (po == NULL) {
        return 0;
    }

    po->po_pkt.pkt_type = XQC_PTYPE_INIT;
    po->po_pkt.pkt_pns  = XQC_PNS_INIT;
    po->po_pkt.pkt_num  = pkt_num;

    /* SCID = client's user_scid; DCID supplied by caller. */
    memcpy(po->po_pkt.pkt_scid.cid_buf,
           cli_conn->scid_set.user_scid.cid_buf,
           cli_conn->scid_set.user_scid.cid_len);
    po->po_pkt.pkt_scid.cid_len = cli_conn->scid_set.user_scid.cid_len;

    memcpy(po->po_pkt.pkt_dcid.cid_buf, dcid_buf, dcid_len);
    po->po_pkt.pkt_dcid.cid_len = dcid_len;

    ssize_t hdr_len = xqc_gen_long_packet_header(
        po,
        po->po_pkt.pkt_dcid.cid_buf, po->po_pkt.pkt_dcid.cid_len,
        po->po_pkt.pkt_scid.cid_buf, po->po_pkt.pkt_scid.cid_len,
        NULL, 0, XQC_VERSION_V1, XQC_PKTNO_BITS);
    if (hdr_len <= 0) {
        xqc_packet_out_destroy(po);
        return 0;
    }
    po->po_used_size += hdr_len;

    /* Pad with zero bytes so the wire-format Initial passes the server-side
     * 1200-byte minimum check (xqc_packet_parse_initial). All zero bytes
     * become a single PADDING frame on the receive path. */
    size_t aead_tag = 16; /* AES-128-GCM, matches BoringSSL initial AEAD */
    size_t target_payload =
        (COALESCED_TEST_PKT_TARGET > (size_t)hdr_len + aead_tag)
            ? COALESCED_TEST_PKT_TARGET - (size_t)hdr_len - aead_tag
            : 64;

    if (po->po_used_size + target_payload > po->po_buf_cap) {
        xqc_packet_out_destroy(po);
        return 0;
    }
    memset(po->po_buf + po->po_used_size, 0x00, target_payload);
    po->po_used_size += target_payload;

    size_t enc_len = 0;
    xqc_int_t ret = xqc_packet_encrypt_buf(cli_conn, po, out_buf,
                                           out_buf_cap, &enc_len);
    xqc_packet_out_destroy(po);
    if (ret != XQC_OK) {
        return 0;
    }
    return enc_len;
}


/*
 * Boilerplate: stand up a client+server engine pair, drive a real Initial
 * from client to server so the server-side connection exists.
 */
static int
coalesced_test_setup(coalesced_ctx_t *cli, coalesced_ctx_t *svr)
{
    cli->engine = coalesced_create_engine(cli, XQC_ENGINE_CLIENT);
    svr->engine = coalesced_create_engine(svr, XQC_ENGINE_SERVER);
    if (cli->engine == NULL || svr->engine == NULL) {
        return -1;
    }

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    const xqc_cid_t *cid = xqc_connect(cli->engine, &conn_settings,
                                       NULL, 0, "", 0, &conn_ssl_config,
                                       NULL, 0, "transport", cli);
    if (cid == NULL || cli->c == NULL) {
        return -1;
    }

    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);
    struct sockaddr_in6 local_addr;
    socklen_t local_addrlen = sizeof(local_addr);

    xqc_engine_packet_process(svr->engine, cli->buf, cli->buf_len,
                              (struct sockaddr *)&local_addr, local_addrlen,
                              (struct sockaddr *)&peer_addr, peer_addrlen,
                              xqc_now(), svr);

    return svr->c == NULL ? -1 : 0;
}


static void
coalesced_test_teardown(coalesced_ctx_t *cli, coalesced_ctx_t *svr)
{
    if (cli->engine != NULL) {
        if (cli->c != NULL) {
            xqc_conn_close(cli->engine, &cli->cid);
        }
        xqc_engine_destroy(cli->engine);
    }
    if (svr->engine != NULL) {
        if (svr->c != NULL) {
            xqc_conn_close(svr->engine, &svr->cid);
        }
        xqc_engine_destroy(svr->engine);
    }
}


/* T1 - regression: a single Initial in a datagram never trips the new
 * mismatch branch (drop counter must remain at its baseline). */
void
xqc_test_coalesced_single_pkt(void)
{
    coalesced_ctx_t cli = {0};
    coalesced_ctx_t svr = {0};

    if (coalesced_test_setup(&cli, &svr) != 0) {
        CU_FAIL("coalesced_test_setup failed");
        coalesced_test_teardown(&cli, &svr);
        return;
    }

    uint32_t baseline = svr.c->packet_dropped_count;

    uint8_t enc[2048];
    size_t enc_len = build_initial_pkt(
        cli.c,
        cli.c->dcid_set.current_dcid.cid_buf,
        cli.c->dcid_set.current_dcid.cid_len,
        1, enc, sizeof(enc));
    CU_ASSERT(enc_len > 0);

    (void)xqc_conn_process_packet(svr.c, enc, enc_len, xqc_now());

    /* Single packet must never increment the dropped count via the new
     * coalesced-mismatch branch. */
    CU_ASSERT_EQUAL(svr.c->packet_dropped_count, baseline);

    coalesced_test_teardown(&cli, &svr);
}


/* T2 - core reverse-validation: a coalesced Initial(A) + Initial(B) datagram
 * with A != B must drop exactly one packet (the offender) and keep
 * processing the rest of the datagram. */
void
xqc_test_coalesced_dcid_mismatch(void)
{
    coalesced_ctx_t cli = {0};
    coalesced_ctx_t svr = {0};

    if (coalesced_test_setup(&cli, &svr) != 0) {
        CU_FAIL("coalesced_test_setup failed");
        coalesced_test_teardown(&cli, &svr);
        return;
    }

    uint32_t baseline_dropped = svr.c->packet_dropped_count;
    uint32_t baseline_rcvd    = svr.c->rcv_pkt_stats.conn_rcvd_pkts;

    /* DCID A: client's view of the current DCID. */
    uint8_t dcid_a[XQC_MAX_CID_LEN];
    uint8_t dcid_a_len = cli.c->dcid_set.current_dcid.cid_len;
    memcpy(dcid_a, cli.c->dcid_set.current_dcid.cid_buf, dcid_a_len);

    /* DCID B: same length, first byte flipped. */
    uint8_t dcid_b[XQC_MAX_CID_LEN];
    uint8_t dcid_b_len = dcid_a_len;
    memcpy(dcid_b, dcid_a, dcid_a_len);
    dcid_b[0] ^= 0xFF;

    uint8_t enc1[2048];
    size_t enc1_len = build_initial_pkt(cli.c, dcid_a, dcid_a_len, 1,
                                        enc1, sizeof(enc1));
    CU_ASSERT(enc1_len > 0);

    uint8_t enc2[2048];
    size_t enc2_len = build_initial_pkt(cli.c, dcid_b, dcid_b_len, 2,
                                        enc2, sizeof(enc2));
    CU_ASSERT(enc2_len > 0);

    uint8_t combined[8192];
    CU_ASSERT(enc1_len + enc2_len <= sizeof(combined));
    memcpy(combined, enc1, enc1_len);
    memcpy(combined + enc1_len, enc2, enc2_len);

    xqc_int_t ret = xqc_conn_process_packet(svr.c, combined,
                                            enc1_len + enc2_len, xqc_now());
    /* The function must return cleanly (non-fatal): the second packet was
     * dropped but the first was processed. */
    CU_ASSERT_EQUAL(ret, XQC_OK);

    /* Exactly one drop attributable to the new branch. */
    CU_ASSERT_EQUAL(svr.c->packet_dropped_count, baseline_dropped + 1);

    /* The first packet must have been logged as received. */
    CU_ASSERT(svr.c->rcv_pkt_stats.conn_rcvd_pkts > baseline_rcvd);

    coalesced_test_teardown(&cli, &svr);
}


/* T3 - boundary: when both coalesced Initials share the same DCID, the new
 * branch must NOT trip. */
void
xqc_test_coalesced_dcid_match(void)
{
    coalesced_ctx_t cli = {0};
    coalesced_ctx_t svr = {0};

    if (coalesced_test_setup(&cli, &svr) != 0) {
        CU_FAIL("coalesced_test_setup failed");
        coalesced_test_teardown(&cli, &svr);
        return;
    }

    uint32_t baseline_dropped = svr.c->packet_dropped_count;

    uint8_t dcid_a[XQC_MAX_CID_LEN];
    uint8_t dcid_a_len = cli.c->dcid_set.current_dcid.cid_len;
    memcpy(dcid_a, cli.c->dcid_set.current_dcid.cid_buf, dcid_a_len);

    uint8_t enc1[2048];
    size_t enc1_len = build_initial_pkt(cli.c, dcid_a, dcid_a_len, 1,
                                        enc1, sizeof(enc1));
    CU_ASSERT(enc1_len > 0);

    uint8_t enc2[2048];
    size_t enc2_len = build_initial_pkt(cli.c, dcid_a, dcid_a_len, 2,
                                        enc2, sizeof(enc2));
    CU_ASSERT(enc2_len > 0);

    uint8_t combined[8192];
    CU_ASSERT(enc1_len + enc2_len <= sizeof(combined));
    memcpy(combined, enc1, enc1_len);
    memcpy(combined + enc1_len, enc2, enc2_len);

    (void)xqc_conn_process_packet(svr.c, combined,
                                  enc1_len + enc2_len, xqc_now());

    /* DCIDs match; the new branch must stay silent. */
    CU_ASSERT_EQUAL(svr.c->packet_dropped_count, baseline_dropped);

    coalesced_test_teardown(&cli, &svr);
}


/* T4 - boundary: same byte prefix but different length must still mismatch
 * (xqc_cid_is_equal first compares cid_len). */
void
xqc_test_coalesced_dcid_len_mismatch(void)
{
    coalesced_ctx_t cli = {0};
    coalesced_ctx_t svr = {0};

    if (coalesced_test_setup(&cli, &svr) != 0) {
        CU_FAIL("coalesced_test_setup failed");
        coalesced_test_teardown(&cli, &svr);
        return;
    }

    uint32_t baseline_dropped = svr.c->packet_dropped_count;

    uint8_t dcid_a[XQC_MAX_CID_LEN];
    uint8_t dcid_a_len = cli.c->dcid_set.current_dcid.cid_len;
    memcpy(dcid_a, cli.c->dcid_set.current_dcid.cid_buf, dcid_a_len);

    /* DCID B: prefix of A, shorter length (dcid_a_len > 4 by default). */
    uint8_t dcid_b[XQC_MAX_CID_LEN];
    uint8_t dcid_b_len = (dcid_a_len > 4) ? (uint8_t)(dcid_a_len - 4) : (uint8_t)4;
    memcpy(dcid_b, dcid_a, dcid_b_len);

    uint8_t enc1[2048];
    size_t enc1_len = build_initial_pkt(cli.c, dcid_a, dcid_a_len, 1,
                                        enc1, sizeof(enc1));
    CU_ASSERT(enc1_len > 0);

    uint8_t enc2[2048];
    size_t enc2_len = build_initial_pkt(cli.c, dcid_b, dcid_b_len, 2,
                                        enc2, sizeof(enc2));
    CU_ASSERT(enc2_len > 0);

    uint8_t combined[8192];
    CU_ASSERT(enc1_len + enc2_len <= sizeof(combined));
    memcpy(combined, enc1, enc1_len);
    memcpy(combined + enc1_len, enc2, enc2_len);

    (void)xqc_conn_process_packet(svr.c, combined,
                                  enc1_len + enc2_len, xqc_now());

    CU_ASSERT_EQUAL(svr.c->packet_dropped_count, baseline_dropped + 1);

    coalesced_test_teardown(&cli, &svr);
}


/* T5 - extension: A + B + A. The middle packet must be dropped, the third
 * (which matches first_dcid) must be accepted again - so drop count is
 * exactly 1 (no double-counting, no spurious accept-then-mismatch). */
void
xqc_test_coalesced_dcid_a_b_a(void)
{
    coalesced_ctx_t cli = {0};
    coalesced_ctx_t svr = {0};

    if (coalesced_test_setup(&cli, &svr) != 0) {
        CU_FAIL("coalesced_test_setup failed");
        coalesced_test_teardown(&cli, &svr);
        return;
    }

    uint32_t baseline_dropped = svr.c->packet_dropped_count;

    uint8_t dcid_a[XQC_MAX_CID_LEN];
    uint8_t dcid_a_len = cli.c->dcid_set.current_dcid.cid_len;
    memcpy(dcid_a, cli.c->dcid_set.current_dcid.cid_buf, dcid_a_len);

    uint8_t dcid_b[XQC_MAX_CID_LEN];
    uint8_t dcid_b_len = dcid_a_len;
    memcpy(dcid_b, dcid_a, dcid_a_len);
    dcid_b[0] ^= 0xFF;

    uint8_t enc1[2048], enc2[2048], enc3[2048];
    size_t l1 = build_initial_pkt(cli.c, dcid_a, dcid_a_len, 1, enc1, sizeof(enc1));
    size_t l2 = build_initial_pkt(cli.c, dcid_b, dcid_b_len, 2, enc2, sizeof(enc2));
    size_t l3 = build_initial_pkt(cli.c, dcid_a, dcid_a_len, 3, enc3, sizeof(enc3));
    CU_ASSERT(l1 > 0 && l2 > 0 && l3 > 0);

    uint8_t combined[8192];
    CU_ASSERT(l1 + l2 + l3 <= sizeof(combined));
    size_t off = 0;
    memcpy(combined + off, enc1, l1); off += l1;
    memcpy(combined + off, enc2, l2); off += l2;
    memcpy(combined + off, enc3, l3); off += l3;

    (void)xqc_conn_process_packet(svr.c, combined, off, xqc_now());

    /* Only the middle packet should have been dropped. */
    CU_ASSERT_EQUAL(svr.c->packet_dropped_count, baseline_dropped + 1);

    coalesced_test_teardown(&cli, &svr);
}
