/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>

#include "xqc_packet_test.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "xquic/xquic_typedef.h"
#include "xquic/xquic.h"
#include "src/common/xqc_str.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"


#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_LONG_HEADER_PACKET_B "\xC0\x00\x00\x00\x01\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89"

#define XQC_TEST_CHECK_CID "ab3f120acdef0089"

void
xqc_test_packet_parse_cid(unsigned char *buf, size_t size, int is_short)
{
    unsigned char dcid_buf[XQC_MAX_CID_LEN * 2];
    unsigned char scid_buf[XQC_MAX_CID_LEN * 2];

    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);

    xqc_cid_t dcid, scid;
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    xqc_int_t rc = xqc_packet_parse_cid(&dcid, &scid, engine->config->cid_len, buf, size);
    CU_ASSERT(rc == XQC_OK);

    xqc_hex_dump(dcid_buf, dcid.cid_buf, dcid.cid_len);
    xqc_hex_dump(scid_buf, scid.cid_buf, scid.cid_len);

    CU_ASSERT(((size_t)dcid.cid_len * 2) == (sizeof(XQC_TEST_CHECK_CID)-1));
    CU_ASSERT(memcmp((unsigned char *)XQC_TEST_CHECK_CID, dcid_buf, ((size_t)dcid.cid_len * 2)) == 0);

    if (!is_short) {
        CU_ASSERT(((size_t)scid.cid_len * 2) == (sizeof(XQC_TEST_CHECK_CID)-1));
        CU_ASSERT(memcmp((unsigned char *)XQC_TEST_CHECK_CID, scid_buf, ((size_t)scid.cid_len * 2)) == 0);
    }

    xqc_engine_destroy(engine);
}

void
xqc_test_short_header_packet_parse_cid()
{
    xqc_test_packet_parse_cid((unsigned char *)XQC_TEST_SHORT_HEADER_PACKET_A,
                              sizeof(XQC_TEST_SHORT_HEADER_PACKET_A)-1, 1);
}

void
xqc_test_long_header_packet_parse_cid()
{
    xqc_test_packet_parse_cid((unsigned char *)XQC_TEST_LONG_HEADER_PACKET_B,
                              sizeof(XQC_TEST_LONG_HEADER_PACKET_B)-1, 0);
}





extern xqc_usec_t xqc_now();



typedef struct test_ctx {
    xqc_engine_t        *engine;
    xqc_connection_t    *c;
    xqc_cid_t            cid;
    char                 buf[2048];
    size_t               buf_len;
} test_ctx;


ssize_t
xqc_test_server_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    test_ctx *tctx = (test_ctx *)conn_user_data;
    memcpy(tctx->buf, buf, size);
    tctx->buf_len = size;

    return size;
}

int
xqc_test_server_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    test_ctx *tctx = (test_ctx *)user_data;
    tctx->c = conn;
    memcpy(&tctx->cid, cid, sizeof(xqc_cid_t));

    xqc_conn_set_alp_user_data(conn, tctx);

    return 0;
}

ssize_t
xqc_test_client_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    test_ctx *tctx = (test_ctx *)conn_user_data;
    memcpy(tctx->buf, buf, size);
    tctx->buf_len = size;

    return size;
}

int
xqc_test_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    test_ctx *tctx = (test_ctx *)user_data;
    tctx->c = conn;
    memcpy(&tctx->cid, cid, sizeof(xqc_cid_t));

    xqc_conn_set_alp_user_data(conn, tctx);

    return 0;
}

void
xqc_test_set_event_timer(xqc_msec_t wake_after, void *engine_user_data)
{
    return;
}

xqc_engine_t *
test_create_engine_buf_server(test_ctx *tctx)
{
    xqc_engine_ssl_config_t  engine_ssl_config;
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    engine_ssl_config.session_ticket_key_len = 0;
    engine_ssl_config.session_ticket_key_data = NULL;

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_test_set_event_timer,
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = xqc_test_server_write,
    };

    xqc_app_proto_callbacks_t transport_cbs = {
        .conn_cbs.conn_create_notify = xqc_test_server_conn_create_notify,
    };

    xqc_conn_settings_t conn_settings;
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_SERVER, NULL, &engine_ssl_config,
                                             &callback, &tcbs, tctx);
    if (engine == NULL) {
        return NULL;
    }

    /* transport ALPN */
    xqc_engine_register_alpn(engine, "transport", 9, &transport_cbs, NULL);

    return engine;
}



xqc_engine_t *
test_create_engine_buf_client(test_ctx *tctx)
{
    xqc_engine_ssl_config_t  engine_ssl_config;
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    engine_ssl_config.session_ticket_key_len = 0;
    engine_ssl_config.session_ticket_key_data = NULL;

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_test_set_event_timer,
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = xqc_test_client_write,
    };

    xqc_app_proto_callbacks_t transport_cbs = {
        .conn_cbs.conn_create_notify = xqc_test_client_conn_create_notify,
    };

    xqc_conn_settings_t conn_settings;
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT, NULL, &engine_ssl_config,
                                             &callback, &tcbs, tctx);
    if (engine == NULL) {
        return NULL;
    }

    /* transport ALPN */
    xqc_engine_register_alpn(engine, "transport", 9, &transport_cbs, NULL);

    return engine;
}


void
xqc_test_packet_encrypt_hp_sample_boundary()
{
    test_ctx         svr_tctx   = {0};
    test_ctx         cli_tctx   = {0};

    svr_tctx.engine = test_create_engine_buf_server(&svr_tctx);
    cli_tctx.engine = test_create_engine_buf_client(&cli_tctx);

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(xqc_conn_settings_t));
    conn_settings.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    xqc_connect(cli_tctx.engine, &conn_settings, NULL, 0, "", 0,
                &conn_ssl_config, NULL, 0, "transport", &cli_tctx);

    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);

    struct sockaddr_in6 local_addr;
    socklen_t local_addrlen = sizeof(local_addr);

    xqc_engine_packet_process(svr_tctx.engine, cli_tctx.buf, cli_tctx.buf_len,
                              (struct sockaddr *)&local_addr, local_addrlen,
                              (struct sockaddr *)&peer_addr, peer_addrlen, xqc_now(), &svr_tctx);

    xqc_packet_out_t *po = xqc_packet_out_create(2048);
    CU_ASSERT(po != NULL);

    memcpy(po->po_pkt.pkt_scid.cid_buf, cli_tctx.c->scid_set.user_scid.cid_buf,
           cli_tctx.c->scid_set.user_scid.cid_len);
    po->po_pkt.pkt_scid.cid_len = cli_tctx.c->scid_set.user_scid.cid_len;

    memcpy(po->po_pkt.pkt_dcid.cid_buf, cli_tctx.c->dcid_set.current_dcid.cid_buf,
            cli_tctx.c->dcid_set.current_dcid.cid_len);
    po->po_pkt.pkt_dcid.cid_len = cli_tctx.c->dcid_set.current_dcid.cid_len;

    ssize_t po_size = xqc_gen_long_packet_header(
        po, po->po_pkt.pkt_dcid.cid_buf, po->po_pkt.pkt_dcid.cid_len,
        po->po_pkt.pkt_scid.cid_buf, po->po_pkt.pkt_scid.cid_len,
        NULL, 0, XQC_VERSION_V1, XQC_PKTNO_BITS);
    CU_ASSERT(po_size > 0);
    po->po_used_size += po_size;

    uint8_t enc_buf[2048];
    size_t enc_len = 0;
    xqc_int_t ret = xqc_packet_encrypt_buf(cli_tctx.c, po, enc_buf, sizeof(enc_buf), &enc_len);
    CU_ASSERT(ret == XQC_OK);

    xqc_packet_out_destroy(po);
    xqc_conn_close(cli_tctx.engine, &cli_tctx.cid);
    xqc_engine_destroy(cli_tctx.engine);

    xqc_conn_close(svr_tctx.engine, &svr_tctx.cid);
    xqc_engine_destroy(svr_tctx.engine);
}


void
xqc_test_empty_pkt()
{
    test_ctx         svr_tctx   = {0};
    test_ctx         cli_tctx   = {0};
    xqc_packet_out_t *po        = NULL;

    svr_tctx.engine = test_create_engine_buf_server(&svr_tctx);
    cli_tctx.engine = test_create_engine_buf_client(&cli_tctx);

    CU_ASSERT(svr_tctx.engine != NULL);
    CU_ASSERT(cli_tctx.engine != NULL);
    if (svr_tctx.engine == NULL || cli_tctx.engine == NULL) {
        goto finish;
    }

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(xqc_conn_settings_t));
    conn_settings.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    /* create client instance, will trigger create_notiry and write_socket */
    const xqc_cid_t *cid = xqc_connect(cli_tctx.engine, &conn_settings,
                                       NULL, 0, "", 0, &conn_ssl_config,
                                       NULL, 0, "transport", &cli_tctx);
    CU_ASSERT(cid != NULL);
    CU_ASSERT(cli_tctx.c != NULL);
    if (cid == NULL || cli_tctx.c == NULL) {
        goto finish;
    }

    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);

    struct sockaddr_in6 local_addr;
    socklen_t local_addrlen = sizeof(local_addr);

    /* server will process the initial packet and get the secret of initial pns */
    xqc_engine_packet_process(svr_tctx.engine, cli_tctx.buf, cli_tctx.buf_len,
                              (struct sockaddr *)&local_addr, local_addrlen,
                              (struct sockaddr *)&peer_addr, peer_addrlen, xqc_now(), &svr_tctx);

    CU_ASSERT(svr_tctx.c != NULL);
    if (svr_tctx.c == NULL) {
        goto finish;
    }

    /* generate an Initial pkt with no payload */
    po = xqc_packet_out_create(2048);
    CU_ASSERT(po != NULL);
    if (po == NULL) {
        goto finish;
    }

    memcpy(po->po_pkt.pkt_scid.cid_buf, cli_tctx.c->scid_set.user_scid.cid_buf,
           cli_tctx.c->scid_set.user_scid.cid_len);
    po->po_pkt.pkt_scid.cid_len = cli_tctx.c->scid_set.user_scid.cid_len;

    memcpy(po->po_pkt.pkt_dcid.cid_buf, cli_tctx.c->dcid_set.current_dcid.cid_buf,
            cli_tctx.c->dcid_set.current_dcid.cid_len);
    po->po_pkt.pkt_dcid.cid_len = cli_tctx.c->dcid_set.current_dcid.cid_len;

    ssize_t po_size = xqc_gen_long_packet_header(
        po, po->po_pkt.pkt_dcid.cid_buf, po->po_pkt.pkt_dcid.cid_len,
        po->po_pkt.pkt_scid.cid_buf, po->po_pkt.pkt_scid.cid_len,
        NULL, 0, XQC_VERSION_V1, XQC_PKTNO_BITS);
    CU_ASSERT(po_size > 0);
    po->po_used_size += po_size;

    /* client encrypt the Initial pkt */
    xqc_int_t ret = xqc_packet_encrypt(cli_tctx.c, po);
    CU_ASSERT(ret == XQC_OK);

    /* server decrypt the Initial pkt */
    ret = xqc_conn_process_packet(svr_tctx.c, cli_tctx.c->enc_pkt,
                                  cli_tctx.c->enc_pkt_len, xqc_now());
    CU_ASSERT(svr_tctx.c->conn_err == TRA_PROTOCOL_VIOLATION);


finish:
    if (po != NULL) {
        xqc_packet_out_destroy(po);
    }

    if (cli_tctx.engine != NULL) {
        if (cli_tctx.c != NULL) {
            xqc_conn_close(cli_tctx.engine, &cli_tctx.cid);
        }
        xqc_engine_destroy(cli_tctx.engine);
    }

    if (svr_tctx.engine != NULL) {
        if (svr_tctx.c != NULL) {
            xqc_conn_close(svr_tctx.engine, &svr_tctx.cid);
        }
        xqc_engine_destroy(svr_tctx.engine);
    }
}


/*
 * Tests for RFC 9000 Section 12.2: when one QUIC packet inside a
 * coalesced UDP datagram fails with a tolerant error (decryption
 * failure, unknown version, etc.), the implementation MUST still
 * attempt to process the remaining packets in the same datagram.
 * Pre-fix code did `goto end` after the first tolerant error, which
 * silently dropped every subsequent coalesced packet. The fix in
 * xqc_conn_process_packet skips past the failing packet via
 * `pos = packet_in->last > pos ? packet_in->last : end; continue;`.
 */

/*
 * Build a synthetic Initial-typed long-header QUIC packet with a
 * well-formed header and a parseable Length(i) field. The encrypted
 * body is intentionally garbage so that AEAD decryption fails with a
 * tolerant error (-XQC_EDECRYPT). Crucially xqc_packet_parse_initial
 * sets packet_in->last = pos + length BEFORE decryption runs, which
 * is exactly the precondition the fix relies on to advance to the
 * next coalesced packet. Returns total bytes written.
 */
static size_t
xqc_test_build_synthetic_initial(unsigned char *buf, size_t cap)
{
    /* payload length (Packet Number + AEAD-protected body, including
     * the 16-byte AEAD tag). 64 leaves enough for the 16-byte HP
     * sample (which starts at pktno_offset + 4) without spilling
     * past the packet boundary. */
    const uint64_t length = 64;

    size_t off = 0;

    /* first byte: 1 1 0 0 R R P P -> Initial, 1-byte packet number */
    buf[off++] = 0xC0;

    /* version: QUIC v1 */
    buf[off++] = 0x00;
    buf[off++] = 0x00;
    buf[off++] = 0x00;
    buf[off++] = 0x01;

    /* dcid_len = 8, dcid = 0x01..0x08 */
    buf[off++] = 0x08;
    for (int i = 0; i < 8; i++) {
        buf[off++] = (unsigned char)(0x01 + i);
    }

    /* scid_len = 8, scid = 0x09..0x10 */
    buf[off++] = 0x08;
    for (int i = 0; i < 8; i++) {
        buf[off++] = (unsigned char)(0x09 + i);
    }

    /* token_len = 0 (1-byte vint) */
    buf[off++] = 0x00;

    /* Length (2-byte vint, 0x40 sets prefix bits = 01) */
    buf[off++] = (unsigned char)(0x40 | ((length >> 8) & 0x3f));
    buf[off++] = (unsigned char)(length & 0xff);

    /* "encrypted" body: garbage. Must be exactly `length` bytes so
     * that parse_initial accepts it (no overflow vs datagram end). */
    for (uint64_t i = 0; i < length; i++) {
        buf[off++] = (unsigned char)(0xAA ^ (i & 0xff));
    }

    (void)cap;
    return off;
}


void
xqc_test_coalesced_continue_after_tolerant_error()
{
    /* the fix lives in xqc_conn_process_packet's coalesced-loop and
     * is independent of TLS state on the server side, so this test
     * brings up only a client engine. That avoids the brittle SSL
     * context teardown-and-recreate path on macOS that intermittently
     * causes test_create_engine_buf_server to fail when invoked after
     * other tests have created and destroyed engines. */
    test_ctx cli_tctx = {0};

    cli_tctx.engine = test_create_engine_buf_client(&cli_tctx);

    CU_ASSERT(cli_tctx.engine != NULL);
    if (cli_tctx.engine == NULL) {
        goto finish;
    }

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(xqc_conn_settings_t));
    conn_settings.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    /* drive xqc_connect on client to bring up the connection_t and
     * its Initial-level TLS keys */
    const xqc_cid_t *cid = xqc_connect(cli_tctx.engine, &conn_settings,
                                       NULL, 0, "", 0, &conn_ssl_config,
                                       NULL, 0, "transport", &cli_tctx);
    CU_ASSERT(cid != NULL);
    CU_ASSERT(cli_tctx.c != NULL);
    if (cid == NULL || cli_tctx.c == NULL) {
        goto finish;
    }

    /* build a synthetic 2-packet coalesced UDP datagram:
     *   pkt 1: well-formed Initial header, parseable Length, garbage
     *          body -> tolerant -XQC_EDECRYPT after parse_initial set
     *          packet_in->last to the packet boundary
     *   pkt 2: a single 0x00 byte -> matches neither short nor long
     *          header masks, returns -XQC_EIGNORE_PKT (also tolerant)
     *
     * The observable: rcv_pkt_stats.conn_rcvd_pkts is bumped once per
     * iteration of xqc_conn_process_packet's inner loop. With the fix
     * the loop should reach packet 2 and the counter increments by 2.
     * Without the fix the old `goto end` aborts after packet 1 and
     * the counter only increments by 1.
     */
    unsigned char dgram[256];
    size_t pkt1_len = xqc_test_build_synthetic_initial(dgram, sizeof(dgram));
    CU_ASSERT(pkt1_len > 0 && pkt1_len < sizeof(dgram));
    dgram[pkt1_len] = 0x00;
    size_t total = pkt1_len + 1;

    uint32_t before = cli_tctx.c->rcv_pkt_stats.conn_rcvd_pkts;
    xqc_int_t ret = xqc_conn_process_packet(cli_tctx.c,
                                            dgram, total, xqc_now());
    uint32_t after = cli_tctx.c->rcv_pkt_stats.conn_rcvd_pkts;

    /* tolerant errors must be swallowed by xqc_conn_process_packet */
    CU_ASSERT(ret == XQC_OK);

    /* with the fix in place we should see BOTH packets visited */
    CU_ASSERT(after - before == 2);

finish:
    if (cli_tctx.engine != NULL) {
        if (cli_tctx.c != NULL) {
            xqc_conn_close(cli_tctx.engine, &cli_tctx.cid);
        }
        xqc_engine_destroy(cli_tctx.engine);
    }
}


void
xqc_test_coalesced_zero_progress_terminates()
{
    test_ctx cli_tctx = {0};

    cli_tctx.engine = test_create_engine_buf_client(&cli_tctx);

    CU_ASSERT(cli_tctx.engine != NULL);
    if (cli_tctx.engine == NULL) {
        goto finish;
    }

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(xqc_conn_settings_t));
    conn_settings.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    const xqc_cid_t *cid = xqc_connect(cli_tctx.engine, &conn_settings,
                                       NULL, 0, "", 0, &conn_ssl_config,
                                       NULL, 0, "transport", &cli_tctx);
    CU_ASSERT(cid != NULL);
    CU_ASSERT(cli_tctx.c != NULL);
    if (cid == NULL || cli_tctx.c == NULL) {
        goto finish;
    }

    /* degenerate datagram: a single byte that triggers -XQC_EIGNORE_PKT
     * inside xqc_packet_parse_single BEFORE any parser advances
     * packet_in->last. Pre-fix code zeroed `pos` via the now-removed
     * `packet_in->pos = packet_in->last; goto end;` path; post-fix
     * code falls back to `pos = end` because last did not advance.
     * Either way the function must return XQC_OK and terminate (no
     * infinite loop, no crash). This pins down the safety fallback in
     * the new conditional `pos = packet_in->last > pos ? ... : end;`. */
    unsigned char dgram[1] = { 0x00 };

    xqc_int_t ret = xqc_conn_process_packet(cli_tctx.c,
                                            dgram, sizeof(dgram), xqc_now());
    CU_ASSERT(ret == XQC_OK);

finish:
    if (cli_tctx.engine != NULL) {
        if (cli_tctx.c != NULL) {
            xqc_conn_close(cli_tctx.engine, &cli_tctx.cid);
        }
        xqc_engine_destroy(cli_tctx.engine);
    }
}
