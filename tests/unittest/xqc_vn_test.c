/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "xqc_vn_test.h"
#include "xquic/xquic.h"
#include "xquic/xquic_typedef.h"
#include "xquic/xqc_errno.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_client.h"
#include "src/common/xqc_log.h"


/*
 * Walkthrough
 * -----------
 *
 *   client engine + connection in CLIENT_INITIAL_SENT state
 *                            |
 *                            v
 *   hand-crafted VN datagram (long header, version=0)
 *                            |
 *           +----------------+-----------------+
 *           |                                  |
 *           v                                  v
 *   xqc_conn_process_packet (T1/T2/T6)  xqc_packet_parse_version_negotiation (T3/T4/T5)
 *           |                                  |
 *           v                                  v
 *   assertions on conn_state / conn_err / conn_flag / buf
 *
 * The connection lives behind a buf-backed write_socket so we can prove
 * "no CONNECTION_CLOSE was emitted" by snapshotting buf_len before and
 * after the VN injection and asserting they are identical.
 */


/* ----- minimal test context (separate from xqc_packet_test.c) ----- */

typedef struct vn_ctx_s {
    xqc_engine_t        *engine;
    xqc_connection_t    *c;
    xqc_cid_t            cid;
    unsigned char        buf[2048];
    size_t               buf_len;
    int                  write_count;
} vn_ctx_t;


static ssize_t
vn_test_client_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    vn_ctx_t *ctx = (vn_ctx_t *)conn_user_data;
    if (size <= sizeof(ctx->buf)) {
        memcpy(ctx->buf, buf, size);
        ctx->buf_len = size;
    }
    ctx->write_count++;
    return (ssize_t)size;
}


static int
vn_test_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    vn_ctx_t *ctx = (vn_ctx_t *)user_data;
    ctx->c = conn;
    memcpy(&ctx->cid, cid, sizeof(xqc_cid_t));
    xqc_conn_set_alp_user_data(conn, ctx);
    return 0;
}


static void
vn_test_set_event_timer(xqc_msec_t wake_after, void *engine_user_data)
{
    return;
}


static xqc_engine_t *
vn_test_create_client_engine(vn_ctx_t *ctx)
{
    xqc_engine_ssl_config_t  ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    ssl_cfg.private_key_file = "./server.key";
    ssl_cfg.cert_file = "./server.crt";
    ssl_cfg.ciphers = XQC_TLS_CIPHERS;
    ssl_cfg.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t cb = {
        .set_event_timer = vn_test_set_event_timer,
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = vn_test_client_write,
    };

    xqc_app_proto_callbacks_t alp_cbs = {
        .conn_cbs.conn_create_notify = vn_test_client_conn_create_notify,
    };

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT, NULL, &ssl_cfg,
                                             &cb, &tcbs, ctx);
    if (engine == NULL) {
        return NULL;
    }

    xqc_engine_register_alpn(engine, "transport", 9, &alp_cbs, NULL);
    return engine;
}


/* Bootstrap a client connection in CLIENT_INITIAL_SENT. Returns 1 on success. */
static int
vn_test_start_client(vn_ctx_t *ctx)
{
    ctx->engine = vn_test_create_client_engine(ctx);
    if (ctx->engine == NULL) {
        return 0;
    }

    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    cs.proto_version = XQC_VERSION_V1;

    xqc_conn_ssl_config_t cssl;
    memset(&cssl, 0, sizeof(cssl));

    const xqc_cid_t *cid = xqc_connect(ctx->engine, &cs, NULL, 0, "", 0, &cssl,
                                       NULL, 0, "transport", ctx);
    if (cid == NULL || ctx->c == NULL) {
        return 0;
    }

    /* xqc_connect drives conn_logic synchronously, so the Initial datagram
     * has already been handed to vn_test_client_write by the time we get
     * here.  State should be CLIENT_INITIAL_SENT.
     */
    return 1;
}


static void
vn_test_teardown(vn_ctx_t *ctx)
{
    if (ctx->engine != NULL) {
        if (ctx->c != NULL) {
            xqc_conn_close(ctx->engine, &ctx->cid);
        }
        xqc_engine_destroy(ctx->engine);
        ctx->engine = NULL;
        ctx->c = NULL;
    }
}


/* ----- VN packet constructor ----- */

/*
 * Build a Version Negotiation datagram per RFC 9000 §17.2.1.
 *
 *   header_byte: caller chooses; must have 0x80 (long-header bit) set.
 *   vn_dcid    : DCID field on the wire (peer's view of the destination).
 *   vn_scid    : SCID field on the wire (peer's source CID).
 *   versions   : array of versions to advertise; each emitted big-endian.
 *
 * Returns the total byte length written into out.
 */
static size_t
build_vn_packet(unsigned char *out, size_t out_cap,
    uint8_t header_byte,
    const unsigned char *vn_dcid, uint8_t dcid_len,
    const unsigned char *vn_scid, uint8_t scid_len,
    const uint32_t *versions, uint32_t version_count)
{
    size_t need = 1 + 4 + 1 + dcid_len + 1 + scid_len + 4 * version_count;
    if (need > out_cap) {
        return 0;
    }

    size_t off = 0;
    out[off++] = header_byte;
    /* version field = 0x00000000 (marks the packet as a VN packet) */
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;

    out[off++] = dcid_len;
    if (dcid_len > 0) {
        memcpy(out + off, vn_dcid, dcid_len);
        off += dcid_len;
    }

    out[off++] = scid_len;
    if (scid_len > 0) {
        memcpy(out + off, vn_scid, scid_len);
        off += scid_len;
    }

    for (uint32_t i = 0; i < version_count; i++) {
        uint32_t v = versions[i];
        out[off++] = (unsigned char)((v >> 24) & 0xff);
        out[off++] = (unsigned char)((v >> 16) & 0xff);
        out[off++] = (unsigned char)((v >> 8) & 0xff);
        out[off++] = (unsigned char)(v & 0xff);
    }

    return off;
}


/*
 * Drive xqc_packet_parse_version_negotiation directly. Skips the long
 * header dispatch and just populates pi_pkt with the wire CIDs the
 * caller wants the parser to see. Returns the parser's return value.
 */
static xqc_int_t
invoke_vn_parser(xqc_connection_t *c,
    const unsigned char *wire_dcid, uint8_t wire_dcid_len,
    const unsigned char *wire_scid, uint8_t wire_scid_len,
    const uint32_t *versions, uint32_t version_count)
{
    /* Build a wire-format buffer purely so the parser has a real
     * version-list region to walk (its position is set just past the
     * SCID, matching xqc_packet_parse_long_header's contract).
     */
    unsigned char buf[256];
    size_t total = build_vn_packet(buf, sizeof(buf), 0x80,
                                   wire_dcid, wire_dcid_len,
                                   wire_scid, wire_scid_len,
                                   versions, version_count);
    if (total == 0) {
        return -XQC_EILLPKT;
    }

    xqc_packet_in_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    xqc_packet_in_init(&pkt, buf, total, NULL, 0, 0);

    /* xqc_packet_parse_long_header would have populated these fields
     * before dispatching to the VN parser; emulate that here so we can
     * exercise the parser in isolation.
     */
    pkt.pi_pkt.pkt_dcid.cid_len = wire_dcid_len;
    if (wire_dcid_len > 0) {
        memcpy(pkt.pi_pkt.pkt_dcid.cid_buf, wire_dcid, wire_dcid_len);
    }
    pkt.pi_pkt.pkt_scid.cid_len = wire_scid_len;
    if (wire_scid_len > 0) {
        memcpy(pkt.pi_pkt.pkt_scid.cid_buf, wire_scid, wire_scid_len);
    }

    /* Position pos past the long header prefix + DCID/SCID, exactly
     * where the dispatch in xqc_packet_parse_long_header would land.
     */
    pkt.pos = (unsigned char *)pkt.buf + 1 + 4 + 1 + wire_dcid_len + 1 + wire_scid_len;
    pkt.last = (unsigned char *)pkt.buf + total;

    return xqc_packet_parse_version_negotiation(c, &pkt);
}


/* =====================  TEST CASES  ===================== */

/*
 * T1: a valid Version Negotiation carrying only a foreign version MUST
 *     drive the client into CLOSED with conn_err = TRA_VERSION_NEGOTIATION_ERROR,
 *     and MUST NOT cause a packet to be written (no CONNECTION_CLOSE).
 */
void
xqc_test_vn_abort_on_unsupported_version(void)
{
    vn_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (!vn_test_start_client(&ctx)) {
        CU_FAIL("client engine bootstrap failed");
        vn_test_teardown(&ctx);
        return;
    }

    /* Sanity: the connection should be sitting in CLIENT_INITIAL_SENT
     * after xqc_connect (driven synchronously by xqc_engine_conn_logic).
     */
    CU_ASSERT(ctx.c->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT);
    CU_ASSERT(ctx.c->conn_err == 0);

    /* Snapshot the buffer state so we can prove no extra write occurs. */
    size_t buf_len_before = ctx.buf_len;
    int    writes_before  = ctx.write_count;
    unsigned char buf_snapshot[2048];
    memcpy(buf_snapshot, ctx.buf, buf_len_before);

    uint32_t versions[] = { 0xfaceb002 };  /* RFC 9000 reserved test version, deliberately not V1 */

    xqc_int_t ret = invoke_vn_parser(ctx.c,
                                     ctx.c->initial_scid.cid_buf, ctx.c->initial_scid.cid_len,
                                     ctx.c->original_dcid.cid_buf, ctx.c->original_dcid.cid_len,
                                     versions, 1);

    /* Parser MUST surface the abort to the caller. */
    CU_ASSERT(ret == -XQC_EVERSION_NEGOTIATION);

    /* Connection state MUST be CLOSED. */
    CU_ASSERT(ctx.c->conn_state == XQC_CONN_STATE_CLOSED);

    /* conn_err MUST carry the library-internal VN abort code. */
    CU_ASSERT(ctx.c->conn_err == TRA_VERSION_NEGOTIATION_ERROR);

    /* Error / closing flags MUST be set. */
    CU_ASSERT(ctx.c->conn_flag & XQC_CONN_FLAG_ERROR);
    CU_ASSERT(ctx.c->conn_flag & XQC_CONN_FLAG_CLOSING_NOTIFY);

    /* And critically: NO new packet was emitted (CONNECTION_CLOSE forbidden
     * in the VN response because keys are not yet established). */
    CU_ASSERT(ctx.write_count == writes_before);
    CU_ASSERT(ctx.buf_len == buf_len_before);
    CU_ASSERT(memcmp(ctx.buf, buf_snapshot, buf_len_before) == 0);

    vn_test_teardown(&ctx);
}


/*
 * T2: a VN packet whose Supported Version list contains the client's
 *     current version MUST be discarded silently (treated as forged),
 *     leaving the connection untouched.
 */
void
xqc_test_vn_downgrade_protection_when_version_matches(void)
{
    vn_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (!vn_test_start_client(&ctx)) {
        CU_FAIL("client engine bootstrap failed");
        vn_test_teardown(&ctx);
        return;
    }

    CU_ASSERT(ctx.c->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT);
    CU_ASSERT(ctx.c->conn_err == 0);
    size_t buf_len_before = ctx.buf_len;
    int    writes_before  = ctx.write_count;

    /* Build a VN list that includes the client's current (negotiated)
     * version. xqc_proto_version_value[XQC_VERSION_V1] == 0x00000001. */
    extern const uint32_t xqc_proto_version_value[];
    uint32_t versions[] = { xqc_proto_version_value[XQC_VERSION_V1], 0xdeadbeef };

    xqc_int_t ret = invoke_vn_parser(ctx.c,
                                     ctx.c->initial_scid.cid_buf, ctx.c->initial_scid.cid_len,
                                     ctx.c->original_dcid.cid_buf, ctx.c->original_dcid.cid_len,
                                     versions, 2);

    /* RFC §6.2: the packet is discarded; the parser returns OK to signal
     * "consumed, nothing to do". */
    CU_ASSERT(ret == XQC_OK);

    /* State and error must be untouched. */
    CU_ASSERT(ctx.c->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT);
    CU_ASSERT(ctx.c->conn_err == 0);
    CU_ASSERT((ctx.c->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    /* No new send. */
    CU_ASSERT(ctx.write_count == writes_before);
    CU_ASSERT(ctx.buf_len == buf_len_before);

    vn_test_teardown(&ctx);
}


/*
 * T3: a VN packet whose DCID does NOT echo the client's SCID MUST be
 *     rejected with -XQC_EILLPKT and MUST NOT alter the connection.
 */
void
xqc_test_vn_reject_when_dcid_mismatch(void)
{
    vn_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (!vn_test_start_client(&ctx)) {
        CU_FAIL("client engine bootstrap failed");
        vn_test_teardown(&ctx);
        return;
    }

    CU_ASSERT(ctx.c->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT);
    size_t buf_len_before = ctx.buf_len;
    int    writes_before  = ctx.write_count;

    /* Corrupt the DCID by flipping every bit -- guaranteed unequal. */
    unsigned char bogus_dcid[XQC_MAX_CID_LEN];
    uint8_t       bogus_dcid_len = ctx.c->initial_scid.cid_len;
    for (uint8_t i = 0; i < bogus_dcid_len; i++) {
        bogus_dcid[i] = (unsigned char)~ctx.c->initial_scid.cid_buf[i];
    }

    uint32_t versions[] = { 0xfaceb002 };
    xqc_int_t ret = invoke_vn_parser(ctx.c,
                                     bogus_dcid, bogus_dcid_len,
                                     ctx.c->original_dcid.cid_buf, ctx.c->original_dcid.cid_len,
                                     versions, 1);

    /* Reverse-CID validation should refuse the packet. */
    CU_ASSERT(ret == -XQC_EILLPKT);

    /* Connection unchanged. */
    CU_ASSERT(ctx.c->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT);
    CU_ASSERT(ctx.c->conn_err == 0);
    CU_ASSERT((ctx.c->conn_flag & XQC_CONN_FLAG_ERROR) == 0);
    CU_ASSERT(ctx.write_count == writes_before);
    CU_ASSERT(ctx.buf_len == buf_len_before);

    vn_test_teardown(&ctx);
}


/*
 * T4: a VN packet whose SCID does NOT echo the client's DCID MUST be
 *     rejected with -XQC_EILLPKT and MUST NOT alter the connection.
 */
void
xqc_test_vn_reject_when_scid_mismatch(void)
{
    vn_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (!vn_test_start_client(&ctx)) {
        CU_FAIL("client engine bootstrap failed");
        vn_test_teardown(&ctx);
        return;
    }

    size_t buf_len_before = ctx.buf_len;
    int    writes_before  = ctx.write_count;

    unsigned char bogus_scid[XQC_MAX_CID_LEN];
    uint8_t       bogus_scid_len = ctx.c->original_dcid.cid_len;
    for (uint8_t i = 0; i < bogus_scid_len; i++) {
        bogus_scid[i] = (unsigned char)~ctx.c->original_dcid.cid_buf[i];
    }

    uint32_t versions[] = { 0xfaceb002 };
    xqc_int_t ret = invoke_vn_parser(ctx.c,
                                     ctx.c->initial_scid.cid_buf, ctx.c->initial_scid.cid_len,
                                     bogus_scid, bogus_scid_len,
                                     versions, 1);

    CU_ASSERT(ret == -XQC_EILLPKT);
    CU_ASSERT(ctx.c->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT);
    CU_ASSERT(ctx.c->conn_err == 0);
    CU_ASSERT(ctx.write_count == writes_before);
    CU_ASSERT(ctx.buf_len == buf_len_before);

    vn_test_teardown(&ctx);
}


/*
 * T5: a VN packet received after the client has left CLIENT_INITIAL_SENT
 *     MUST be dropped (-XQC_ESTATE). Guards against attacker re-triggering
 *     a second VN abort once the connection has progressed.
 */
void
xqc_test_vn_reject_when_state_not_initial_sent(void)
{
    vn_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (!vn_test_start_client(&ctx)) {
        CU_FAIL("client engine bootstrap failed");
        vn_test_teardown(&ctx);
        return;
    }

    /* Force the connection past CLIENT_INITIAL_SENT. */
    ctx.c->conn_state = XQC_CONN_STATE_CLIENT_INITIAL_RECVD;
    size_t buf_len_before = ctx.buf_len;
    int    writes_before  = ctx.write_count;

    uint32_t versions[] = { 0xfaceb002 };
    xqc_int_t ret = invoke_vn_parser(ctx.c,
                                     ctx.c->initial_scid.cid_buf, ctx.c->initial_scid.cid_len,
                                     ctx.c->original_dcid.cid_buf, ctx.c->original_dcid.cid_len,
                                     versions, 1);

    CU_ASSERT(ret == -XQC_ESTATE);

    /* State stays where we put it; no abort triggered. */
    CU_ASSERT(ctx.c->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_RECVD);
    CU_ASSERT(ctx.c->conn_err == 0);
    CU_ASSERT((ctx.c->conn_flag & XQC_CONN_FLAG_ERROR) == 0);
    CU_ASSERT(ctx.write_count == writes_before);
    CU_ASSERT(ctx.buf_len == buf_len_before);

    vn_test_teardown(&ctx);
}


/*
 * T6: a VN packet advertising MANY foreign versions still MUST trigger
 *     the abort; the client must not invent a fallback negotiation.
 *     Also smoke-tests that the parser's version-list buffering is sane
 *     for non-trivial counts.
 */
void
xqc_test_vn_abort_on_multi_unsupported_versions(void)
{
    vn_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (!vn_test_start_client(&ctx)) {
        CU_FAIL("client engine bootstrap failed");
        vn_test_teardown(&ctx);
        return;
    }

    CU_ASSERT(ctx.c->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT);
    size_t buf_len_before = ctx.buf_len;
    int    writes_before  = ctx.write_count;

    uint32_t versions[] = {
        0xfaceb002, 0xfaceb003, 0xff000020, 0xff00001c,
        0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00
    };
    uint32_t vcount = sizeof(versions) / sizeof(versions[0]);

    xqc_int_t ret = invoke_vn_parser(ctx.c,
                                     ctx.c->initial_scid.cid_buf, ctx.c->initial_scid.cid_len,
                                     ctx.c->original_dcid.cid_buf, ctx.c->original_dcid.cid_len,
                                     versions, vcount);

    CU_ASSERT(ret == -XQC_EVERSION_NEGOTIATION);
    CU_ASSERT(ctx.c->conn_state == XQC_CONN_STATE_CLOSED);
    CU_ASSERT(ctx.c->conn_err == TRA_VERSION_NEGOTIATION_ERROR);
    CU_ASSERT(ctx.c->conn_flag & XQC_CONN_FLAG_ERROR);
    CU_ASSERT(ctx.write_count == writes_before);
    CU_ASSERT(ctx.buf_len == buf_len_before);

    vn_test_teardown(&ctx);
}
